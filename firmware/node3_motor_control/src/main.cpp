/*
 * Node 3 -- Motor-Control ECU. Executes ONLY commands approved by Node 4. Drives 2x L298 -> 4 motors.
 *
 * STATUS: not yet implemented -- placeholder.
 * See docs/CANARY_Architecture_Summary.docx for the full spec this
 * node must follow (message format, verification order, etc).
 */
#include <Arduino.h>

void setup() {
  Serial.begin(115200);
}

void loop() {
}
