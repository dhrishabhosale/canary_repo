/*
 * =====================================================================
 * CANARY - Node 1: Wheel Encoder ECU Firmware
 * 
 * Target: ESP32 DevKit V1
 * Inputs:
 *   - Front Encoder Motor (Left side):
 *       Phase A (Interrupt) -> GPIO 18
 *       Phase B (Direction) -> GPIO 19
 *   - Rear Encoder Motor (Right side):
 *       Phase A (Interrupt) -> GPIO 25
 *       Phase B (Direction) -> GPIO 26
 * 
 * Pipeline:
 *  1. Capture encoder pulses via hardware interrupts.
 *  2. Every 50 ms (20 Hz), calculate rotational speed (RPM) for Left & Right.
 *  3. Map Left speed to FL & RL; Right speed to FR & RR.
 *  4. Format 4 CANARY messages (subtypes WHEEL_FL, FR, RL, RR).
 *  5. Compute BLAKE3 hash-tree freshness tokens.
 *  6. Sign with Ed25519 (Monocypher).
 *  7. Transmit via ESP-NOW to Node 4 (Security ECU) and vehicle network.
 * =====================================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>

extern "C" {
#include "src/canary_protocol.h"
#include "src/canary_crypto.h"
#include "src/canary_freshness.h"
}

// ---------------------------------------------------------------------
// Pin Definitions
// ---------------------------------------------------------------------
#define ENC_LEFT_A_PIN    18   // Phase A (Interrupt)
#define ENC_LEFT_B_PIN    19   // Phase B (Direction)
#define ENC_RIGHT_A_PIN   25   // Phase A (Interrupt)
#define ENC_RIGHT_B_PIN   26   // Phase B (Direction)

// ---------------------------------------------------------------------
// Encoder Physical Specifications
// N20 150RPM motor: ~3 pulses per motor revolution * gear ratio
// Effective counts per wheel revolution ~ 900
// ---------------------------------------------------------------------
static const float ENCODER_COUNTS_PER_REV = 900.0f;

// Volatile pulse counters modified inside ISR
static volatile int32_t left_pulse_count = 0;
static volatile int32_t right_pulse_count = 0;

// ISR for Left Encoder
void IRAM_ATTR isr_left_encoder() {
  int b_val = digitalRead(ENC_LEFT_B_PIN);
  if (b_val == HIGH) {
    left_pulse_count++;
  } else {
    left_pulse_count--;
  }
}

// ISR for Right Encoder (Inverted to match forward vehicle direction)
void IRAM_ATTR isr_right_encoder() {
  int b_val = digitalRead(ENC_RIGHT_B_PIN);
  if (b_val == HIGH) {
    right_pulse_count--;
  } else {
    right_pulse_count++;
  }
}

// ---------------------------------------------------------------------
// Node 1 Cryptographic Identity & Provisioned Keys
// ---------------------------------------------------------------------
static const uint8_t NODE1_SEED[CANARY_SEED_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static const uint8_t NODE1_TREE_SEED[CANARY_TREE_SEED_LEN] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

static uint8_t node1_secret_key[CANARY_SECRET_KEY_LEN];
static uint8_t node1_public_key[CANARY_PUBLIC_KEY_LEN];

static uint32_t current_epoch = 1;
static uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static uint32_t tx_success_count = 0;
static uint32_t tx_fail_count = 0;

// ESP-NOW Callback
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void on_data_sent(const wifi_tx_info_t *info, esp_now_send_status_t status) {
  if (status == ESP_NOW_SEND_SUCCESS) tx_success_count++;
  else tx_fail_count++;
}
#else
void on_data_sent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  if (status == ESP_NOW_SEND_SUCCESS) tx_success_count++;
  else tx_fail_count++;
}
#endif

// ---------------------------------------------------------------------
// CANARY Layer 1 Packet Assembler & Transmitter
// ---------------------------------------------------------------------
static bool send_canary_wheel_subpacket(canary_wheel_subtype_t subtype, float rpm_val) {
  canary_message_t msg;
  memset(&msg, 0, sizeof(msg));

  msg.body.sender_id = CANARY_NODE_ENCODER;
  msg.body.msg_type  = CANARY_MSG_WHEEL_SPEED;
  msg.body.subtype   = (uint8_t)subtype;
  msg.body.epoch     = current_epoch++;

  // Payload: fixed-point integer scaled x1000 (milli-RPM)
  msg.body.payload   = (int32_t)roundf(rpm_val * 1000.0f);

  // Compute Layer 1 BLAKE3 freshness token from tree root seed
  canary_freshness_derive(msg.body.freshness, NODE1_TREE_SEED, msg.body.epoch);

  // Compute Ed25519 signature over msg.body (27 bytes)
  canary_sign(&msg, node1_secret_key);

  // Transmit over ESP-NOW
  esp_err_t result = esp_now_send(broadcast_mac, (const uint8_t *)&msg, CANARY_MESSAGE_SIZE);
  return (result == ESP_OK);
}

// ---------------------------------------------------------------------
// Setup & Loop
// ---------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(1200);

  Serial.println("\n=======================================================");
  Serial.println("  CANARY - Node 1: Wheel Encoder ECU Firmware");
  Serial.println("  Layer 1 Ed25519 + BLAKE3 Freshness + ESP-NOW");
  Serial.println("=======================================================");

  // 1. Configure Encoder GPIOs with internal pull-ups
  pinMode(ENC_LEFT_A_PIN, INPUT_PULLUP);
  pinMode(ENC_LEFT_B_PIN, INPUT_PULLUP);
  pinMode(ENC_RIGHT_A_PIN, INPUT_PULLUP);
  pinMode(ENC_RIGHT_B_PIN, INPUT_PULLUP);

  // Attach hardware interrupts on Phase A rising edges
  attachInterrupt(digitalPinToInterrupt(ENC_LEFT_A_PIN), isr_left_encoder, RISING);
  attachInterrupt(digitalPinToInterrupt(ENC_RIGHT_A_PIN), isr_right_encoder, RISING);
  Serial.println("[Encoders] Hardware interrupts initialized on GPIO 18 & 25.");

  // 2. Derive Node 1 cryptographic keypair
  canary_keygen(node1_secret_key, node1_public_key, NODE1_SEED);
  Serial.printf("[Crypto] Node 1 Public Key: ");
  for (int i = 0; i < CANARY_PUBLIC_KEY_LEN; i++) {
    Serial.printf("%02X", node1_public_key[i]);
  }
  Serial.printf("\n[Crypto] Signature Size: %u bytes, Packet Wire Size: %u bytes\n",
                (unsigned)CANARY_SIG_LEN, (unsigned)CANARY_MESSAGE_SIZE);

  // 3. Initialize ESP-NOW
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  if (esp_now_init() != ESP_OK) {
    Serial.println("[ESP-NOW] Initialization failed! Halting.");
    while (1) { delay(1000); }
  }

  esp_now_peer_info_t peerInfo;
  memset(&peerInfo, 0, sizeof(peerInfo));
  memcpy(peerInfo.peer_addr, broadcast_mac, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;
  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("[ESP-NOW] Failed to add broadcast peer!");
  } else {
    Serial.println("[ESP-NOW] Broadcast peer registered.");
  }

  esp_now_register_send_cb(on_data_sent);

  Serial.println("[CANARY Node 1] Operational. Starting broadcast loop @ 20 Hz...\n");
}

void loop() {
  static uint32_t last_sample_time = 0;
  static uint32_t last_log_time = 0;
  uint32_t now = millis();

  // 20 Hz sampling and transmission cycle (every 50 ms)
  if (now - last_sample_time >= 50) {
    uint32_t dt_ms = now - last_sample_time;
    last_sample_time = now;

    // Atomically read and reset pulse counters
    noInterrupts();
    int32_t pulses_left = left_pulse_count;
    int32_t pulses_right = right_pulse_count;
    left_pulse_count = 0;
    right_pulse_count = 0;
    interrupts();

    // Convert pulses in dt_ms window to RPM:
    // revs = pulses / ENCODER_COUNTS_PER_REV
    // RPM = (revs / (dt_ms / 1000.0)) * 60.0
    float left_rpm = ((float)pulses_left / ENCODER_COUNTS_PER_REV) * (60000.0f / (float)dt_ms);
    float right_rpm = ((float)pulses_right / ENCODER_COUNTS_PER_REV) * (60000.0f / (float)dt_ms);

    // Left encoder maps to FL & RL; Right encoder maps to FR & RR
    float fl_rpm = left_rpm;
    float rl_rpm = left_rpm;
    float fr_rpm = right_rpm;
    float rr_rpm = right_rpm;

    // Send 4 signed CANARY frames
    send_canary_wheel_subpacket(CANARY_WHEEL_FL, fl_rpm);
    send_canary_wheel_subpacket(CANARY_WHEEL_FR, fr_rpm);
    send_canary_wheel_subpacket(CANARY_WHEEL_RL, rl_rpm);
    send_canary_wheel_subpacket(CANARY_WHEEL_RR, rr_rpm);

    // Telemetry printout once per second (1 Hz)
    if (now - last_log_time >= 1000) {
      last_log_time = now;
      Serial.printf("[Node 1] Epoch=%-6u | Left: %+6.1f RPM | Right: %+6.1f RPM | [FL:%+5.1f FR:%+5.1f RL:%+5.1f RR:%+5.1f] | TX OK=%u Fail=%u\n",
                    current_epoch, left_rpm, right_rpm, fl_rpm, fr_rpm, rl_rpm, rr_rpm, tx_success_count, tx_fail_count);
    }
  }
}
