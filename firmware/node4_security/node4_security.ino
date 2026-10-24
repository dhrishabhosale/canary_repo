/*
 * CANARY Node 4 - Security/IDS ECU: ESP-NOW receiver + Layer 1 verifier
 *
 * Receives 91-byte CANARY frames, queues them (short Wi-Fi callback), and
 * verifies them in loop() with the shared canary_verify code:
 * trusted sender -> allowlisted stream -> Ed25519 -> BLAKE3 freshness -> replay.
 * Node 5 is never trusted; Node 6 (retired) is never configured.
 *
 * Node 4 holds only PUBLIC keys plus the freshness tree seeds. It never
 * holds a signing key.
 *
 * Telemetry Output:
 *  - USB Serial @ 115200 baud
 *  - Untethered Wi-Fi Hotspot ("CANARY_HOTSPOT" / "canary1234") via UDP broadcast on port 8888
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <WiFiUdp.h>
#include <string.h>

extern "C" {
#include "src/canary_protocol.h"
#include "src/canary_crypto.h"
#include "src/canary_freshness.h"
#include "src/canary_verify.h"
}

static_assert(sizeof(canary_message_t) == 91, "CANARY wire size changed");

// Set to 0 to compile out the serial fault-injection commands.
#define CANARY_N4_SELFTEST 1

// ---------------------------------------------------------------------
// Provisioned verification material (public keys + freshness seeds only)
// ---------------------------------------------------------------------

// EXACT Public Key derived from NODE1_SEED in node1_encoder.ino
static const uint8_t NODE1_PUBLIC_KEY[CANARY_PUBLIC_KEY_LEN] = {
  0xD4, 0xF8, 0xE6, 0xF2, 0x67, 0x27, 0x11, 0x77,
  0xC1, 0x1D, 0x17, 0xD3, 0x98, 0x10, 0xD7, 0x47,
  0x16, 0x65, 0x72, 0xA1, 0xB6, 0xDB, 0x8E, 0x35,
  0x23, 0x63, 0xD9, 0x78, 0x6E, 0xB0, 0x79, 0x83
};

// Tree seed matching node1_encoder.ino
static const uint8_t NODE1_TREE_SEED[CANARY_TREE_SEED_LEN] = {
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

// EXACT Public Key derived from NODE2_SEED in node2_imu.ino
static const bool NODE2_PROVISIONED = true;
static const uint8_t NODE2_PUBLIC_KEY[CANARY_PUBLIC_KEY_LEN] = {
  0xD7, 0xD4, 0x14, 0x1F, 0x72, 0x8F, 0x04, 0xC2,
  0xA2, 0xDB, 0xAD, 0x2E, 0x8D, 0x2B, 0x26, 0xD1,
  0x07, 0x0E, 0x11, 0xE8, 0xDB, 0xB0, 0x25, 0xF5,
  0xB6, 0x6F, 0x75, 0x8F, 0xF3, 0x6F, 0x2D, 0x94
};

// Tree seed matching node2_imu.ino
static const uint8_t NODE2_TREE_SEED[CANARY_TREE_SEED_LEN] = {
  0x42, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
  0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44,
  0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
  0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55
};

// ---------------------------------------------------------------------
static const uint8_t WIFI_CHANNEL = 1;
static QueueHandle_t packetQueue;
static canary_verify_context_t verifier;

// ---------------------------------------------------------------------
// Wireless Telemetry Configuration (Wi-Fi SoftAP + UDP Broadcast)
// ---------------------------------------------------------------------
static const char *AP_SSID = "CANARY_HOTSPOT";
static const char *AP_PASS = "canary1234";
static const uint16_t UDP_PORT = 8888;
static WiFiUDP udp;
static IPAddress broadcastIp(192, 168, 4, 255);

// Helper to send formatted telemetry string to both Serial and UDP
static void n4_printf(const char *fmt, ...) {
  char buf[256];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  Serial.print(buf);

  udp.beginPacket(broadcastIp, UDP_PORT);
  udp.write((const uint8_t*)buf, strlen(buf));
  udp.endPacket();
}

// Written by the Wi-Fi callback, read in loop(): 32-bit, so single accesses are atomic.
static volatile uint32_t rxTotal = 0;
static volatile uint32_t rxBadLen = 0;
static volatile int      lastBadLen = 0;
static volatile uint32_t qDrops = 0;

// Written/read only in loop().
static uint32_t verdictCount[7] = {};      // indexed by canary_verify_result_t
static uint32_t wheelVerified[4] = {};
static int32_t  wheelMilliRpm[4] = {};
static uint32_t imuVerified = 0, imuUnverified = 0;
static int32_t  imuLatest[6] = {};
static uint8_t  imuSeen = 0;
static uint32_t verifyUsMax = 0, verifyUsSum = 0, verifyN = 0;
static uint32_t lastRejectLog[7] = {};

static canary_message_t lastAccepted;
static bool haveLastAccepted = false;

static const char *VERDICT_TEXT[7] = {
  "VERIFIED",
  "REJECT invalid argument",
  "REJECT untrusted sender",
  "REJECT unknown/disallowed stream",
  "REJECT bad signature",
  "REJECT bad freshness",
  "REJECT replay/stale epoch"
};

static bool allZero(const uint8_t *p, size_t n) {
  uint8_t acc = 0;
  for (size_t i = 0; i < n; i++) acc |= p[i];
  return acc == 0;
}

// ---------------------------------------------------------------------
// Wi-Fi task context: no crypto, no printing, no blocking.
// ---------------------------------------------------------------------
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void onReceive(const esp_now_recv_info_t *info,
               const uint8_t *data, int len) {
#else
void onReceive(const uint8_t *mac_addr,
               const uint8_t *data, int len) {
#endif
  rxTotal++;
  if (!data || len != (int)CANARY_MESSAGE_SIZE) {
    lastBadLen = len;
    rxBadLen++;
    return;
  }
  canary_message_t msg;
  memcpy(&msg, data, sizeof(msg));
  if (xQueueSend(packetQueue, &msg, 0) != pdTRUE) qDrops++;
}

// ---------------------------------------------------------------------
// loop() context
// ---------------------------------------------------------------------
static void logVerdict(const canary_message_t &m, int v, const char *tag, bool force) {
  if (!force) {
    uint32_t now = millis();
    if (now - lastRejectLog[v] < 250) return;   // rate-limit per reason
    lastRejectLog[v] = now;
  }
  n4_printf("[N4]%s %s | sender=%u type=%u sub=%u epoch=%lu payload=%ld\n",
                tag, VERDICT_TEXT[v],
                (unsigned)m.body.sender_id, (unsigned)m.body.msg_type,
                (unsigned)m.body.subtype, (unsigned long)m.body.epoch,
                (long)m.body.payload);
}

// Verifies one frame. Returns the verdict (0 = VERIFIED).
static int handleMessage(const canary_message_t &msg, const char *tag, bool force) {
  const uint8_t sub = msg.body.subtype;

  // Legacy IMU path while Node 2 keys are not provisioned: NOT authenticated.
  if (!NODE2_PROVISIONED && msg.body.sender_id == CANARY_NODE_IMU &&
      msg.body.msg_type == CANARY_MSG_IMU_DATA && sub <= 5) {
    imuLatest[sub] = msg.body.payload;
    imuSeen |= (1U << sub);
    imuUnverified++;
    return -1;
  }

  uint32_t t0 = micros();
  int v = (int)canary_verify_message(&verifier, &msg);
  uint32_t dt = micros() - t0;
  verifyUsSum += dt; verifyN++;
  if (dt > verifyUsMax) verifyUsMax = dt;

  if (v < 0 || v > 6) v = 1;
  verdictCount[v]++;

  if (v == (int)CANARY_VERIFY_ACCEPT) {
    if (msg.body.sender_id == CANARY_NODE_ENCODER && sub < 4) {
      wheelMilliRpm[sub] = msg.body.payload;
      wheelVerified[sub]++;
    } else if (msg.body.sender_id == CANARY_NODE_IMU && sub < 6) {
      imuLatest[sub] = msg.body.payload;
      imuSeen |= (1U << sub);
      imuVerified++;
    }
    lastAccepted = msg;
    haveLastAccepted = true;
    if (force) logVerdict(msg, v, tag, true);
  } else {
    logVerdict(msg, v, tag, force);
  }
  return v;
}

#if CANARY_N4_SELFTEST
// Local fault injection: mutates the last VERIFIED frame and feeds it to the
// same verifier. This tests verifier behaviour on the board, NOT the radio.
static void selfTest(char c) {
  if (!haveLastAccepted) { Serial.println("[N4][TEST] no verified frame yet"); return; }
  canary_message_t m = lastAccepted;
  const char *tag = "[TEST]";
  switch (c) {
    case 'r': Serial.println("[N4][TEST] replay of last verified frame"); break;
    case 't': m.body.payload ^= 1;          Serial.println("[N4][TEST] payload bit flipped"); break;
    case 'g': m.signature[0] ^= 1;          Serial.println("[N4][TEST] signature bit flipped"); break;
    case 'f': m.body.sender_id = CANARY_NODE_ATTACKER; Serial.println("[N4][TEST] forged sender = Node 5"); break;
    case 'w': m.body.sender_id = CANARY_NODE_GATEWAY;  Serial.println("[N4][TEST] sender = retired Node 6"); break;
    case 'u': m.body.subtype = 9;           Serial.println("[N4][TEST] disallowed subtype"); break;
    default: return;
  }
  handleMessage(m, tag, true);
}
#endif

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\nCANARY Node 4 - Layer 1 verifier");

  packetQueue = xQueueCreate(64, sizeof(canary_message_t));
  if (!packetQueue) {
    Serial.println("ERROR: queue creation failed");
    return;
  }

  // Configure verification streams (public key + freshness seed only).
  canary_verify_init(&verifier);
  if (allZero(NODE1_PUBLIC_KEY, sizeof NODE1_PUBLIC_KEY)) {
    Serial.println("ERROR: NODE1_PUBLIC_KEY not set; Node 1 frames will be rejected as unknown stream");
  } else {
    for (uint8_t s = CANARY_WHEEL_FL; s <= CANARY_WHEEL_RR; s++) {
      canary_verify_cfg_result_t r = canary_verify_configure_stream(
          &verifier, CANARY_NODE_ENCODER, CANARY_MSG_WHEEL_SPEED, s,
          NODE1_PUBLIC_KEY, NODE1_TREE_SEED);
      if (r != CANARY_VERIFY_CFG_OK)
        Serial.printf("ERROR: configure Node 1 stream %u failed (%d)\n", (unsigned)s, (int)r);
    }
  }
  if (NODE2_PROVISIONED) {
    for (uint8_t s = CANARY_IMU_AX; s <= CANARY_IMU_GZ; s++) {
      canary_verify_cfg_result_t r = canary_verify_configure_stream(
          &verifier, CANARY_NODE_IMU, CANARY_MSG_IMU_DATA, s,
          NODE2_PUBLIC_KEY, NODE2_TREE_SEED);
      if (r != CANARY_VERIFY_CFG_OK)
        Serial.printf("ERROR: configure Node 2 stream %u failed (%d)\n", (unsigned)s, (int)r);
    }
  } else {
    Serial.println("WARNING: Node 2 keys not provisioned; IMU frames are UNVERIFIED");
  }

  // Initialize Wi-Fi in AP+STA mode so ESP-NOW (STA) and Hotspot (AP) coexist on Channel 1
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASS, WIFI_CHANNEL, 0, 4);
  udp.begin(UDP_PORT);
  Serial.printf("[WiFi AP] Hotspot created: '%s' (Pass: '%s') on Channel %u\n", AP_SSID, AP_PASS, (unsigned)WIFI_CHANNEL);
  Serial.printf("[WiFi UDP] Broadcasting live telemetry to 192.168.4.255:%u\n", (unsigned)UDP_PORT);

  if (esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE) != ESP_OK) {
    Serial.println("ERROR: channel setup failed");
    return;
  }

  uint8_t mac[6] = {};
  esp_wifi_get_mac(WIFI_IF_STA, mac);
  Serial.printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X  channel %u\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (unsigned)WIFI_CHANNEL);
  Serial.printf("Expected packet size: %u bytes\n", (unsigned)CANARY_MESSAGE_SIZE);

  if (esp_now_init() != ESP_OK) {
    Serial.println("ERROR: ESP-NOW init failed");
    return;
  }
  if (esp_now_register_recv_cb(onReceive) != ESP_OK) {
    Serial.println("ERROR: callback registration failed");
    return;
  }

  Serial.println("READY: waiting for Node 1 wheel (and Node 2 IMU) frames");
#if CANARY_N4_SELFTEST
  Serial.println("Self-test keys: r=replay t=tamper payload g=bad sig f=Node5 w=Node6 u=bad stream");
#endif
}

void loop() {
  canary_message_t msg;
  uint32_t start = millis();

  // Bounded drain so the 1 Hz report is never starved under load.
  while (packetQueue && xQueueReceive(packetQueue, &msg, 0) == pdTRUE) {
    handleMessage(msg, "", false);
    if (millis() - start >= 40) break;
  }

#if CANARY_N4_SELFTEST
  while (Serial.available()) selfTest((char)Serial.read());

  // Listen for commands via UDP as well
  int packetSize = udp.parsePacket();
  if (packetSize > 0) {
    char c = (char)udp.read();
    selfTest(c);
  }
#endif

  static uint32_t lastReport = 0;
  if (millis() - lastReport >= 1000) {
    lastReport = millis();

    n4_printf("[N4] rx=%lu badLen=%lu (last len %d) qDrops=%lu\n",
                  (unsigned long)rxTotal, (unsigned long)rxBadLen, (int)lastBadLen,
                  (unsigned long)qDrops);
    n4_printf("[N4] verified=%lu | rejected: untrusted=%lu stream=%lu sig=%lu fresh=%lu replay=%lu | verify avg=%luus max=%luus\n",
                  (unsigned long)verdictCount[0], (unsigned long)verdictCount[2],
                  (unsigned long)verdictCount[3], (unsigned long)verdictCount[4],
                  (unsigned long)verdictCount[5], (unsigned long)verdictCount[6],
                  (unsigned long)(verifyN ? verifyUsSum / verifyN : 0),
                  (unsigned long)verifyUsMax);
    verifyUsSum = 0; verifyN = 0; verifyUsMax = 0;

    n4_printf("[N4] Node1 VERIFIED frames: FL=%lu FR=%lu RL=%lu RR=%lu\n",
                  (unsigned long)wheelVerified[0], (unsigned long)wheelVerified[1],
                  (unsigned long)wheelVerified[2], (unsigned long)wheelVerified[3]);
    if (wheelVerified[0] && wheelVerified[1] && wheelVerified[2] && wheelVerified[3]) {
      n4_printf("[N4] Wheel RPM (verified): FL=%+.1f FR=%+.1f RL=%+.1f RR=%+.1f\n",
                    wheelMilliRpm[0] / 1000.0f, wheelMilliRpm[1] / 1000.0f,
                    wheelMilliRpm[2] / 1000.0f, wheelMilliRpm[3] / 1000.0f);
    }

    const char *imuTag = NODE2_PROVISIONED ? "verified" : "UNVERIFIED";
    n4_printf("[N4] IMU frames (%s): %lu\n", imuTag,
                  (unsigned long)(NODE2_PROVISIONED ? imuVerified : imuUnverified));
    if (imuSeen == 0x3F) {
      n4_printf("[N4] Accel [m/s^2] (%s): X=%+.3f Y=%+.3f Z=%+.3f\n", imuTag,
                    imuLatest[0] / 1000.0f, imuLatest[1] / 1000.0f, imuLatest[2] / 1000.0f);
      n4_printf("[N4] Gyro  [rad/s] (%s): X=%+.3f Y=%+.3f Z=%+.3f\n", imuTag,
                    imuLatest[3] / 1000.0f, imuLatest[4] / 1000.0f, imuLatest[5] / 1000.0f);
    }
  }

  delay(1);
}