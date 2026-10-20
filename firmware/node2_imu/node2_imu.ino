#include <Arduino.h>
#include <Wire.h>

#define SDA_PIN 21
#define SCL_PIN 22
#define MPU_ADDR 0x68

void setup() {
  Serial.begin(115200);
  delay(1000);

  Wire.begin(SDA_PIN, SCL_PIN);
  Wire.setClock(50000);
  Wire.setTimeOut(250);

  Serial.println("\nCANARY - Sensor Identity Check");
}

void loop() {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x75);
  uint8_t err = Wire.endTransmission(true);

  if (err == 0) {
    size_t count = Wire.requestFrom(
      (uint8_t)MPU_ADDR, (size_t)1, true
    );

    if (count == 1) {
      uint8_t who = Wire.read();
      Serial.printf("WHO_AM_I = 0x%02X\n", who);
    } else {
      Serial.printf("Read failed: received %u bytes\n",
                    (unsigned)count);
    }
  } else {
    Serial.printf("Register selection error: %u\n", err);
  }

  delay(1000);
}
