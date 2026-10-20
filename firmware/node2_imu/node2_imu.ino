/*
 * =====================================================================
 * CANARY - Node 2: IMU ECU Firmware
 * 
 * Target: ESP32 DevKit V1
 * Sensor: MPU-6050 (GY-521) on I2C (SDA=GPIO21, SCL=GPIO22, VCC=3V3, GND=GND)
 * 
 * Pipeline:
 *  1. Read 6-axis acceleration & angular velocity over I2C.
 *  2. Calibrate & convert to physical units (m/s^2, rad/s).
 *  3. Encode into 91-byte CANARY protocol messages (subtypes AX..GZ).
 *  4. Generate Layer 1 BLAKE3 hash-tree freshness tokens.
 *  5. Sign with Ed25519 (Monocypher).
 *  6. Transmit via ESP-NOW to Node 4 (Security ECU) and the vehicle network.
 * =====================================================================
 */

#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <esp_now.h>

extern "C" {
#include "src/canary_protocol.h"
#include "src/canary_crypto.h"
#include "src/canary_freshness.h"
}

// ---------------------------------------------------------------------
// Pinout & Sensor Constants
// ---------------------------------------------------------------------
#define SDA_PIN 21
#define SCL_PIN 22
#define MPU_ADDR 0x68

// Sensitivity factors:
// ACCEL ±4g -> 8192 LSB/g, 1g = 9.80665 m/s^2
static const float ACCEL_SCALE = 9.80665f / 8192.0f;
// GYRO ±500 deg/s -> 65.5 LSB/(deg/s), 1 deg/s = (PI / 180) rad/s
static const float GYRO_SCALE = (3.141592653589793f / 180.0f) / 65.5f;

// ---------------------------------------------------------------------
// Node 2 Cryptographic Identity & Provisioned Keys
// ---------------------------------------------------------------------
// 32-byte master seed for Node 2 (IMU ECU)
static const uint8_t NODE2_SEED[CANARY_SEED_LEN] = {
    0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72,
    0x82, 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2,
    0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71,
    0x81, 0x91, 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1
};

// 32-byte tree root seed for BLAKE3 freshness derivation
static const uint8_t NODE2_TREE_SEED[CANARY_TREE_SEED_LEN] = {
    0x42, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55
};

static uint8_t node2_secret_key[CANARY_SECRET_KEY_LEN];
static uint8_t node2_public_key[CANARY_PUBLIC_KEY_LEN];

// Monotonic epoch counter across all messages from Node 2
static uint32_t current_epoch = 1;

// Broadcast MAC address (FF:FF:FF:FF:FF:FF) for ESP-NOW mesh
static uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Gyro zero-rate bias offsets (calibrated at boot)
static float gyro_bias_x = 0.0f;
static float gyro_bias_y = 0.0f;
static float gyro_bias_z = 0.0f;

// Transmission statistics
static uint32_t tx_success_count = 0;
static uint32_t tx_fail_count = 0;

// ---------------------------------------------------------------------
// ESP-NOW Callback
// ---------------------------------------------------------------------
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
// MPU-6050 Low-Level Driver
// ---------------------------------------------------------------------
static bool mpu_write_reg(uint8_t reg, uint8_t val) {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(reg);
  Wire.write(val);
  return (Wire.endTransmission(true) == 0);
}

static bool mpu_init() {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x75); // WHO_AM_I
  if (Wire.endTransmission(true) != 0) return false;

  Wire.requestFrom((uint8_t)MPU_ADDR, (size_t)1, true);
  if (!Wire.available()) return false;
  uint8_t who = Wire.read();
  Serial.printf("[MPU6050] Detected Device ID: 0x%02X\n", who);

  // Wake up from sleep (PWR_MGMT_1)
  if (!mpu_write_reg(0x6B, 0x00)) return false;
  delay(50);

  // Select PLL with X-axis gyro reference for stable sampling clock
  if (!mpu_write_reg(0x6B, 0x01)) return false;
  delay(10);

  // Sample rate divider: 1 kHz / (1 + 7) = 125 Hz
  mpu_write_reg(0x19, 0x07);

  // Digital Low Pass Filter: DLPF_CFG = 3 (~44 Hz bandwidth)
  mpu_write_reg(0x1A, 0x03);

  // Gyroscope config: ±500 deg/s (FS_SEL = 1 -> 0x08)
  mpu_write_reg(0x1B, 0x08);

  // Accelerometer config: ±4g (AFS_SEL = 1 -> 0x08)
  mpu_write_reg(0x1C, 0x08);

  return true;
}

static bool mpu_read_raw(int16_t &ax, int16_t &ay, int16_t &az,
                         int16_t &gx, int16_t &gy, int16_t &gz) {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x3B); // ACCEL_XOUT_H
  if (Wire.endTransmission(false) != 0) return false; // Repeated start

  size_t count = Wire.requestFrom((uint8_t)MPU_ADDR, (size_t)14, true);
  if (count != 14) return false;

  ax = (int16_t)((Wire.read() << 8) | Wire.read());
  ay = (int16_t)((Wire.read() << 8) | Wire.read());
  az = (int16_t)((Wire.read() << 8) | Wire.read());
  Wire.read(); Wire.read(); // Skip internal temperature registers
  gx = (int16_t)((Wire.read() << 8) | Wire.read());
  gy = (int16_t)((Wire.read() << 8) | Wire.read());
  gz = (int16_t)((Wire.read() << 8) | Wire.read());

  return true;
}

static void calibrate_gyro() {
  Serial.println("[MPU6050] Calibrating gyro zero-rate bias (keep stationary)...");
  int32_t sum_gx = 0, sum_gy = 0, sum_gz = 0;
  const int samples = 120;
  int valid = 0;

  for (int i = 0; i < samples; i++) {
    int16_t ax, ay, az, gx, gy, gz;
    if (mpu_read_raw(ax, ay, az, gx, gy, gz)) {
      sum_gx += gx;
      sum_gy += gy;
      sum_gz += gz;
      valid++;
    }
    delay(10);
  }

  if (valid > 60) {
    gyro_bias_x = ((float)sum_gx / valid) * GYRO_SCALE;
    gyro_bias_y = ((float)sum_gy / valid) * GYRO_SCALE;
    gyro_bias_z = ((float)sum_gz / valid) * GYRO_SCALE;
    Serial.printf("[MPU6050] Bias calibrated (rad/s): X=%+.4f, Y=%+.4f, Z=%+.4f\n",
                  gyro_bias_x, gyro_bias_y, gyro_bias_z);
  } else {
    Serial.println("[MPU6050] Warning: Calibration sample count low, using 0 bias.");
  }
}

// ---------------------------------------------------------------------
// CANARY Layer 1 Packet Assembler & Transmitter
// ---------------------------------------------------------------------
static bool send_canary_imu_subpacket(canary_imu_subtype_t subtype, float physical_val) {
  canary_message_t msg;
  memset(&msg, 0, sizeof(msg));

  // Populate signed body
  msg.body.sender_id = CANARY_NODE_IMU;
  msg.body.msg_type  = CANARY_MSG_IMU_DATA;
  msg.body.subtype   = (uint8_t)subtype;
  msg.body.epoch     = current_epoch++;

  // Payload: fixed-point integer scaled x1000 (millirads/s for gyro, milli-m/s^2 for accel)
  msg.body.payload   = (int32_t)roundf(physical_val * 1000.0f);

  // Compute Layer 1 BLAKE3 freshness token from tree root seed
  canary_freshness_derive(msg.body.freshness, NODE2_TREE_SEED, msg.body.epoch);

  // Compute Ed25519 signature over msg.body (27 bytes)
  canary_sign(&msg, node2_secret_key);

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
  Serial.println("  CANARY - Node 2: IMU ECU Firmware");
  Serial.println("  Layer 1 Ed25519 + BLAKE3 Freshness + ESP-NOW");
  Serial.println("=======================================================");

  // 1. Derive Node 2 cryptographic keypair from provisioned seed
  canary_keygen(node2_secret_key, node2_public_key, NODE2_SEED);
  Serial.printf("[Crypto] Node 2 Public Key: ");
  for (int i = 0; i < CANARY_PUBLIC_KEY_LEN; i++) {
    Serial.printf("%02X", node2_public_key[i]);
  }
  Serial.printf("\n[Crypto] Signature Size: %u bytes, Packet Wire Size: %u bytes\n",
                (unsigned)CANARY_SIG_LEN, (unsigned)CANARY_MESSAGE_SIZE);

  // 2. Initialize ESP-NOW wireless interface
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

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
  esp_now_register_send_cb(on_data_sent);
#else
  esp_now_register_send_cb(on_data_sent);
#endif

  // 3. Initialize I2C and MPU-6050
  Wire.begin(SDA_PIN, SCL_PIN);
  Wire.setClock(100000);
  Wire.setTimeOut(250);

  Serial.println("[MPU6050] Connecting to sensor at 0x68...");
  while (!mpu_init()) {
    Serial.println("[MPU6050] Sensor not found or initialization failed! Check wiring (3V3, GND, D21, D22). Retrying...");
    delay(1000);
  }
  Serial.println("[MPU6050] Sensor initialized successfully.");

  // 4. Calibrate stationary offsets
  calibrate_gyro();
  Serial.println("[CANARY Node 2] Operational. Starting broadcast loop @ 20 Hz...\n");
}

void loop() {
  static uint32_t last_sample_time = 0;
  static uint32_t last_log_time = 0;
  uint32_t now = millis();

  // 20 Hz sampling and transmission cycle (every 50 ms)
  if (now - last_sample_time >= 50) {
    last_sample_time = now;

    int16_t raw_ax, raw_ay, raw_az, raw_gx, raw_gy, raw_gz;
    if (mpu_read_raw(raw_ax, raw_ay, raw_az, raw_gx, raw_gy, raw_gz)) {
      // Physical conversion
      float ax = raw_ax * ACCEL_SCALE;
      float ay = raw_ay * ACCEL_SCALE;
      float az = raw_az * ACCEL_SCALE;

      float gx = (raw_gx * GYRO_SCALE) - gyro_bias_x;
      float gy = (raw_gy * GYRO_SCALE) - gyro_bias_y;
      float gz = (raw_gz * GYRO_SCALE) - gyro_bias_z; // Observed yaw rate

      // Authenticate, sign, and transmit all 6 axes
      send_canary_imu_subpacket(CANARY_IMU_AX, ax);
      send_canary_imu_subpacket(CANARY_IMU_AY, ay);
      send_canary_imu_subpacket(CANARY_IMU_AZ, az);
      send_canary_imu_subpacket(CANARY_IMU_GX, gx);
      send_canary_imu_subpacket(CANARY_IMU_GY, gy);
      send_canary_imu_subpacket(CANARY_IMU_GZ, gz);

      // Telemetry printout once per second (1 Hz)
      if (now - last_log_time >= 1000) {
        last_log_time = now;
        Serial.printf("[Node 2] Epoch=%-6u | a=[%+5.2f, %+5.2f, %+5.2f] m/s^2 | w=[%+5.3f, %+5.3f, %+5.3f] rad/s (Yaw: %+5.3f) | TX OK=%u Fail=%u\n",
                      current_epoch, ax, ay, az, gx, gy, gz, gz, tx_success_count, tx_fail_count);
      }
    } else {
      Serial.println("[Node 2 Error] Failed to read I2C burst from MPU-6050!");
    }
  }
}
