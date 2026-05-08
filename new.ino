// Required libraries (install via Arduino Library Manager):
//   WiFiManager       by tzapu
//   ArduinoJson       by Benoit Blanchon
//   NTPClient         by Fabrice Weinberg
// (BearSSL is built into the ESP8266 Arduino core — no extra install needed)

#include <ESP8266WiFi.h>
#include <WiFiManager.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <WiFiClientSecure.h>
#include <ESP8266mDNS.h>
#include <NTPClient.h>
#include <WiFiUdp.h>
#include <bearssl/bearssl_hmac.h>

// ─── Server endpoints ─────────────────────────────────────────────────────────
const char* serverRegisterUrl = "https://iot-gas-leakage-detector.onrender.com/api/register";
const char* serverGasUrl      = "https://iot-gas-leakage-detector.onrender.com/api/gas";

// ─── Hardware ─────────────────────────────────────────────────────────────────
const int gasPin    = A0;
const int buzzerPin = D5;

// ─── Timing ───────────────────────────────────────────────────────────────────
const unsigned long sendInterval    = 5000;
const unsigned long ntpSyncInterval = 60000;

// ─── NTP (UTC, offset = 0) ────────────────────────────────────────────────────
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP, "pool.ntp.org", 0, 60000);

// ─── Device credentials ───────────────────────────────────────────────────────
ESP8266WebServer localServer(80);
const char* deviceFile = "/device.json";

String deviceId     = "";
String apiKey       = "";
String dashboardUrl = "";
String deviceName   = "";

// ─── HMAC-SHA256 (BearSSL) ────────────────────────────────────────────────────
String computeHMAC(const String& key, const String& message) {
  br_hmac_key_context kc;
  br_hmac_context     ctx;
  br_hmac_key_init(&kc, &br_sha256_vtable,
                   (const uint8_t*)key.c_str(), key.length());
  br_hmac_init(&ctx, &kc, 0);
  br_hmac_update(&ctx, (const uint8_t*)message.c_str(), message.length());
  uint8_t result[32];
  br_hmac_out(&ctx, result);
  String hex = "";
  hex.reserve(64);
  for (int i = 0; i < 32; i++) {
    if (result[i] < 0x10) hex += '0';
    hex += String(result[i], HEX);
  }
  return hex;
}

// ─── LittleFS helpers ─────────────────────────────────────────────────────────
void saveDeviceInfo() {
  DynamicJsonDocument doc(256);
  doc["deviceId"]     = deviceId;
  doc["apiKey"]       = apiKey;
  doc["dashboardUrl"] = dashboardUrl;
  doc["deviceName"]   = deviceName;
  File f = LittleFS.open(deviceFile, "w");
  if (f) { serializeJson(doc, f); f.close(); }
}

bool loadDeviceInfo() {
  if (!LittleFS.exists(deviceFile)) return false;
  File f = LittleFS.open(deviceFile, "r");
  if (!f) return false;
  DynamicJsonDocument doc(512);
  DeserializationError err = deserializeJson(doc, f);
  f.close();
  if (err) return false;
  deviceId     = String(doc["deviceId"].as<const char*>());
  apiKey       = String(doc["apiKey"].as<const char*>());
  dashboardUrl = String(doc["dashboardUrl"].as<const char*>());
  deviceName   = String(doc["deviceName"].as<const char*>());
  return (deviceId.length() > 0 && apiKey.length() > 0);
}

// ─── Local info page ──────────────────────────────────────────────────────────
void handleRoot() {
  String html = "<html><body style='font-family:Arial;padding:16px;'>";
  html += "<h3>Gas Sensor — Device Info</h3>";
  if (deviceId.length() && dashboardUrl.length()) {
    html += "<p>Status: <b>Registered</b></p>";
    html += "<p>Device ID: <b>" + deviceId + "</b></p>";
    html += "<p>Dashboard: <a href='" + dashboardUrl + "' target='_blank'>" + dashboardUrl + "</a></p>";
  } else {
    html += "<p>Not yet registered with cloud server.</p>";
  }
  html += "</body></html>";
  localServer.send(200, "text/html", html);
}

// ─── Cloud registration ───────────────────────────────────────────────────────
bool registerDeviceToCloud() {
  if (WiFi.status() != WL_CONNECTED) return false;
  deviceName = String("GasSensor-") + WiFi.macAddress();
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  http.begin(client, serverRegisterUrl);
  http.addHeader("Content-Type", "application/json");
  String payload = "{\"deviceName\":\"" + deviceName + "\"}";
  int code = http.POST(payload);
  if (code != 200 && code != 201) {
    Serial.printf("Register failed, HTTP %d\n", code);
    http.end();
    return false;
  }
  String resp = http.getString();
  http.end();
  DynamicJsonDocument doc(512);
  if (deserializeJson(doc, resp)) {
    Serial.println("Failed to parse register response");
    return false;
  }
  deviceId     = String(doc["deviceId"].as<const char*>());
  apiKey       = String(doc["apiKey"].as<const char*>());
  dashboardUrl = String(doc["dashboardUrl"].as<const char*>());
  saveDeviceInfo();
  Serial.println("Registered OK");
  Serial.println("  deviceId:     " + deviceId);
  Serial.println("  dashboardUrl: " + dashboardUrl);
  return true;
}

// ─── Send reading with HMAC ───────────────────────────────────────────────────
bool sendReading(int gasValue) {
  if (WiFi.status() != WL_CONNECTED) return false;

  timeClient.update();
  unsigned long utcSec = timeClient.getEpochTime();

  Serial.printf("UTC epoch: %lu\n", utcSec);

  if (utcSec < 1000000000UL) {
    Serial.println("NTP not synced yet, skipping");
    return false;
  }

  // Append "000" instead of multiplying — avoids 32-bit overflow on ESP8266
  String timestampMs = String(utcSec) + "000";

  String message   = deviceId + ":" + String(gasValue) + ":" + timestampMs;
  String signature = computeHMAC(apiKey, message);

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  http.begin(client, serverGasUrl);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(8000);

  String body = "{\"deviceId\":\"" + deviceId + "\","
              + "\"value\":"      + String(gasValue) + ","
              + "\"timestamp\":"  + timestampMs + ","
              + "\"signature\":\"" + signature + "\"}";

  int code = http.POST(body);
  String resp = http.getString();
  Serial.printf("POST /api/gas -> HTTP %d | %s\n", code, resp.c_str());
  http.end();
  return (code >= 200 && code < 300);
}

// ─── Setup ────────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\nESP8266 Gas Sensor — starting");

  if (!LittleFS.begin()) Serial.println("LittleFS mount failed");

  // ── REMOVE THIS LINE AFTER FIRST SUCCESSFUL REGISTRATION ──
  // LittleFS.remove("/device.json");
  // ──────────────────────────────────────────────────────────

  bool hasInfo = loadDeviceInfo();
  if (hasInfo) {
    Serial.println("Loaded stored credentials:");
    Serial.println("  deviceId: " + deviceId);
  }

  pinMode(buzzerPin, OUTPUT);
  digitalWrite(buzzerPin, LOW);

  WiFiManager wm;
  wm.setConnectTimeout(30);
  if (!wm.autoConnect("GasSensor-Setup")) {
    Serial.println("WiFiManager failed, restarting...");
    delay(2000);
    ESP.restart();
  }
  Serial.println("WiFi connected. IP: " + WiFi.localIP().toString());

  // ── NTP sync — keep trying until we get a real timestamp ──
  timeClient.begin();
  Serial.println("Syncing NTP...");
  int ntpTries = 0;
  while (ntpTries < 20) {
    timeClient.forceUpdate();
    unsigned long t = timeClient.getEpochTime();
    Serial.printf("  NTP attempt %d — UTC epoch: %lu\n", ntpTries + 1, t);
    if (t > 1000000000UL) {
      Serial.println("NTP synced OK");
      break;
    }
    ntpTries++;
    delay(1000);
  }
  if (timeClient.getEpochTime() < 1000000000UL) {
    Serial.println("NTP failed after 20 tries — restarting");
    delay(1000);
    ESP.restart();
  }

  // mDNS
  if (MDNS.begin("gassensor")) Serial.println("mDNS: http://gassensor.local/");
  localServer.on("/", handleRoot);
  localServer.begin();
  Serial.println("Local info page: http://" + WiFi.localIP().toString() + "/");

  if (!hasInfo) {
    Serial.println("No credentials — registering with cloud...");
    int regTries = 0;
    while (!registerDeviceToCloud() && regTries < 5) {
      Serial.printf("Registration attempt %d failed, retrying...\n", regTries + 1);
      regTries++;
      delay(3000);
    }
    if (deviceId.length() == 0) {
      Serial.println("Could not register after 5 tries — restarting");
      delay(1000);
      ESP.restart();
    }
  }
}

// ─── Loop ─────────────────────────────────────────────────────────────────────
unsigned long lastSend    = 0;
unsigned long lastNtpSync = 0;

void loop() {
  localServer.handleClient();
  MDNS.update();

  if (WiFi.status() != WL_CONNECTED) { delay(500); return; }

  if (deviceId.length() == 0) {
    if (!registerDeviceToCloud()) delay(5000);
    return;
  }

  unsigned long now = millis();

  if (now - lastNtpSync >= ntpSyncInterval) {
    lastNtpSync = now;
    timeClient.update();
  }

  if (now - lastSend >= sendInterval) {
    lastSend = now;

    int gasValue = analogRead(gasPin);
    Serial.print("Gas: "); Serial.println(gasValue);

    const int gasThreshold = 400;
    if (gasValue > gasThreshold) {
      Serial.println("HIGH gas — buzzer on");
      for (int i = 0; i < 3; i++) {
        digitalWrite(buzzerPin, HIGH); delay(200);
        digitalWrite(buzzerPin, LOW);  delay(200);
      }
    } else {
      digitalWrite(buzzerPin, LOW);
    }

    if (!sendReading(gasValue)) {
      Serial.println("Send failed — will retry next interval.");
    }
  }
}