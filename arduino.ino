// Required libraries (install via Arduino Library Manager):
//   WiFiManager       by tzapu
//   ArduinoJson       by Benoit Blanchon
//   NTPClient         by Fabrice Weinberg
//   Crypto            by Rhys Weatherley  (provides HMAC + SHA256)

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
#include <Crypto.h>
#include <SHA256.h>
#include <HMAC.h>

// ─── Server endpoints ────────────────────────────────────────────────────────
const char* serverRegisterUrl = "https://iot-gas-leakage-detector.onrender.com/api/register";
const char* serverGasUrl      = "https://iot-gas-leakage-detector.onrender.com/api/gas";

// ─── Hardware ────────────────────────────────────────────────────────────────
const int gasPin    = A0;
const int buzzerPin = D5;

// ─── Timing ──────────────────────────────────────────────────────────────────
const unsigned long sendInterval = 5000;   // ms between readings
const unsigned long ntpSyncInterval = 60000; // re-sync NTP every 60 s

// ─── NTP ─────────────────────────────────────────────────────────────────────
WiFiUDP ntpUDP;
// UTC offset = 0; update interval = 60 s (we call update() ourselves)
NTPClient timeClient(ntpUDP, "pool.ntp.org", 0, 60000);

// ─── Device credentials (persisted to flash) ─────────────────────────────────
ESP8266WebServer localServer(80);
const char* deviceFile = "/device.json";

String deviceId   = "";
String apiKey     = "";
String dashboardUrl = "";
String deviceName = "";

// ─── HMAC helper ─────────────────────────────────────────────────────────────
// Returns lowercase hex HMAC-SHA256 of `message` keyed with `key`.
// message format: "deviceId:value:timestampMs"
String computeHMAC(const String& key, const String& message) {
  HMAC<SHA256> hmac;
  hmac.resetHMAC((const uint8_t*)key.c_str(), key.length());
  hmac.update((const uint8_t*)message.c_str(), message.length());

  uint8_t result[32];
  hmac.finalizeHMAC((const uint8_t*)key.c_str(), key.length(), result, sizeof(result));

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
  doc["deviceId"]    = deviceId;
  doc["apiKey"]      = apiKey;
  doc["dashboardUrl"] = dashboardUrl;
  doc["deviceName"]  = deviceName;
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
  client.setInsecure(); // NOTE: for production, pin the server cert fingerprint
  HTTPClient http;
  http.begin(client, serverRegisterUrl);
  http.addHeader("Content-Type", "application/json");

  String payload = "{\"deviceName\":\"" + deviceName + "\"}";
  int code = http.POST(payload);
  if (code != 200) {
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
  Serial.println("  deviceId:    " + deviceId);
  Serial.println("  dashboardUrl:" + dashboardUrl);
  return true;
}

// ─── Secure reading submission ────────────────────────────────────────────────
// Sends: { deviceId, value, timestamp (ms epoch), signature (HMAC-SHA256 hex) }
// The server verifies the signature — the raw apiKey is never transmitted.
bool sendReading(int gasValue) {
  if (WiFi.status() != WL_CONNECTED) return false;

  // Sync NTP and get current time in milliseconds
  timeClient.update();
  unsigned long timestampMs = (unsigned long)timeClient.getEpochTime() * 1000UL;
  if (timestampMs == 0) {
    Serial.println("NTP time not available, skipping send");
    return false;
  }

  // Build HMAC message and sign it
  String message   = deviceId + ":" + String(gasValue) + ":" + String(timestampMs);
  String signature = computeHMAC(apiKey, message);

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  http.begin(client, serverGasUrl);
  http.addHeader("Content-Type", "application/json");

  // apiKey is NOT sent — server authenticates via HMAC signature only
  String body = "{\"deviceId\":\"" + deviceId + "\","
                + "\"value\":" + String(gasValue) + ","
                + "\"timestamp\":" + String(timestampMs) + ","
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

  bool hasInfo = loadDeviceInfo();
  if (hasInfo) {
    Serial.println("Loaded stored credentials:");
    Serial.println("  deviceId: " + deviceId);
  }

  pinMode(buzzerPin, OUTPUT);
  digitalWrite(buzzerPin, LOW);

  WiFiManager wm;
  if (!wm.autoConnect("GasSensor-Setup")) {
    Serial.println("WiFiManager failed, restarting...");
    delay(2000);
    ESP.restart();
  }
  Serial.println("WiFi connected. IP: " + WiFi.localIP().toString());

  // Start NTP immediately after WiFi connects
  timeClient.begin();
  Serial.println("Syncing NTP...");
  for (int tries = 0; tries < 10 && !timeClient.update(); tries++) delay(500);
  Serial.printf("NTP time: %lu s\n", timeClient.getEpochTime());

  // mDNS — access at http://gassensor.local/
  if (MDNS.begin("gassensor")) Serial.println("mDNS: http://gassensor.local/");

  localServer.on("/", handleRoot);
  localServer.begin();
  Serial.println("Local info page: http://" + WiFi.localIP().toString() + "/");

  if (!hasInfo) {
    Serial.println("No credentials — registering with cloud...");
    if (registerDeviceToCloud()) {
      Serial.println("Registration successful.");
    } else {
      Serial.println("Registration failed — will retry in loop.");
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

  // Retry registration if credentials missing
  if (deviceId.length() == 0) {
    if (!registerDeviceToCloud()) delay(5000);
    return;
  }

  unsigned long now = millis();

  // Periodic NTP re-sync (every 60 s) to keep timestamps accurate
  if (now - lastNtpSync >= ntpSyncInterval) {
    lastNtpSync = now;
    timeClient.update();
  }

  if (now - lastSend >= sendInterval) {
    lastSend = now;

    int gasValue = analogRead(gasPin);
    Serial.print("Gas: "); Serial.println(gasValue);

    // Local buzzer alert (independent of cloud)
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

    // Send to cloud with HMAC authentication
    if (!sendReading(gasValue)) {
      Serial.println("Send failed — will retry next interval.");
    }
  }
}
