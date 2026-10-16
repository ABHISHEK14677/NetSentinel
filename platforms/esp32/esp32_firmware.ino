/*
 * NetSentinel - ESP32 Auxiliary Security Controller Firmware
 * Section 14.8 ESP32 Hardware Logic
 * 
 * Target: ESP32-WROOM-32 / ESP32-S3
 * Features:
 * - HMAC-SHA256 authenticated alert decoding
 * - Visual status RGB LED / NeoPixel patterns by severity
 * - PWM Buzzer tone sequences
 * - Heartbeat ping-pong with Linux Host
 * - Enclosure physical tamper switch interrupt
 * - Fail-safe offline alarm if Linux Host disconnects
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>

// Pin Definitions
#define PIN_LED_RED      21
#define PIN_LED_GREEN    22
#define PIN_LED_BLUE     19
#define PIN_BUZZER       25
#define PIN_TAMPER_SW    18

// Configuration
const char* API_SECRET_KEY = "esp32-authenticated-key-sec-99";
const char* FIRMWARE_VER = "v1.4.2-sec";
unsigned long lastHeartbeatRx = 0;
const unsigned long HOST_TIMEOUT_MS = 20000;
volatile bool tamperTriggered = false;

void IRAM_ATTR onTamperInterrupt() {
    tamperTriggered = true;
}

void setRGB(int r, int g, int b) {
    analogWrite(PIN_LED_RED, r);
    analogWrite(PIN_LED_GREEN, g);
    analogWrite(PIN_LED_BLUE, b);
}

void playBuzzerPattern(int frequency, int durationMs, int pulses) {
    for (int i = 0; i < pulses; i++) {
        tone(PIN_BUZZER, frequency, durationMs);
        delay(durationMs + 50);
    }
    noTone(PIN_BUZZER);
}

void applySeverityPattern(const char* severity) {
    if (strcmp(severity, "Critical") == 0) {
        setRGB(255, 0, 0); // Solid Red
        playBuzzerPattern(2800, 200, 3);
    } else if (strcmp(severity, "High") == 0) {
        setRGB(255, 50, 0); // Orange
        playBuzzerPattern(2000, 150, 2);
    } else if (strcmp(severity, "Medium") == 0) {
        setRGB(255, 200, 0); // Yellow
        playBuzzerPattern(1200, 100, 1);
    } else if (strcmp(severity, "Low") == 0) {
        setRGB(0, 100, 255); // Blue
        playBuzzerPattern(800, 80, 1);
    } else {
        setRGB(0, 255, 0); // Normal Green
        noTone(PIN_BUZZER);
    }
}

bool verifyHMAC(const String& payload, const String& signature, unsigned long timestamp) {
    String msg = String(timestamp) + ":" + payload;
    byte hmacResult[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*)API_SECRET_KEY, strlen(API_SECRET_KEY));
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)msg.c_str(), msg.length());
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);

    char hexBuf[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&hexBuf[i * 2], "%02x", hmacResult[i]);
    }
    hexBuf[64] = 0;

    return signature.equalsIgnoreCase(String(hexBuf));
}

void setup() {
    Serial.begin(115200);
    pinMode(PIN_LED_RED, OUTPUT);
    pinMode(PIN_LED_GREEN, OUTPUT);
    pinMode(PIN_LED_BLUE, OUTPUT);
    pinMode(PIN_BUZZER, OUTPUT);
    pinMode(PIN_TAMPER_SW, INPUT_PULLUP);

    attachInterrupt(digitalPinToInterrupt(PIN_TAMPER_SW), onTamperInterrupt, FALLING);

    // Initial Health OK indicator (Green)
    setRGB(0, 255, 0);
    lastHeartbeatRx = millis();
    Serial.println("{\"device\": \"ESP32\", \"status\": \"READY\", \"fw\": \"1.4.2-sec\"}");
}

void loop() {
    // 1. Check Tamper Sensor
    if (tamperTriggered) {
        tamperTriggered = false;
        setRGB(255, 0, 255); // Magenta alert
        playBuzzerPattern(3500, 500, 2);
        Serial.println("{\"event\": \"TAMPER_ALERT\", \"sensor\": \"ENCLOSURE_SWITCH_OPEN\"}");
    }

    // 2. Fail-Safe Host Disconnect Warning (Section 14.8)
    if (millis() - lastHeartbeatRx > HOST_TIMEOUT_MS) {
        // Host unreachable: Flash amber warning
        setRGB(255, 100, 0);
        delay(300);
        setRGB(0, 0, 0);
        delay(300);
        return;
    }

    // 3. Process Inbound Serial/Network Commands from Linux Node
    if (Serial.available()) {
        String jsonLine = Serial.readStringUntil('\n');
        StaticJsonDocument<1024> doc;
        DeserializationError error = deserializeJson(doc, jsonLine);
        if (!error) {
            const char* sig = doc["signature"];
            unsigned long ts = doc["timestamp"];
            String payloadStr;
            serializeJson(doc["payload"], payloadStr);

            if (verifyHMAC(payloadStr, String(sig), ts)) {
                lastHeartbeatRx = millis();
                const char* cmd = doc["payload"]["cmd"];
                if (strcmp(cmd, "ALERT") == 0) {
                    const char* sev = doc["payload"]["severity"];
                    applySeverityPattern(sev);
                } else if (strcmp(cmd, "PING") == 0) {
                    Serial.println("{\"pong\": true, \"health\": \"OK\"}");
                }
            } else {
                Serial.println("{\"error\": \"AUTH_FAILED\"}");
            }
        }
    }
    delay(50);
}
