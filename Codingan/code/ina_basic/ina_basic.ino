#include <Wire.h>
#include <Adafruit_INA219.h>

// Create an instance of INA219
Adafruit_INA219 ina219;

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    delay(10);  // Wait for the Serial Monitor to connect
  }

  // Initialize I2C communication
  if (!ina219.begin()) {
    Serial.println("Failed to find INA219 chip");
    while (1) {
      delay(10);
    }
  }
  Serial.println("INA219 Initialized.");
  
}

void loop() {
  float shuntVoltage = ina219.getShuntVoltage_mV();  // Shunt voltage (mV)
  float busVoltage = ina219.getBusVoltage_V();       // Bus voltage (V)
  float current_mA = ina219.getCurrent_mA();         // Current (mA)
  float power_mW = ina219.getPower_mW();             // Power (mW)
  
  // Display the values
  Serial.print("Bus Voltage:   "); Serial.print(busVoltage); Serial.println(" V");
  Serial.print("Shunt Voltage: "); Serial.print(shuntVoltage); Serial.println(" mV");
  Serial.print("Current:       "); Serial.print(current_mA); Serial.println(" mA");
  Serial.print("Power:         "); Serial.print(power_mW); Serial.println(" mW");
  Serial.println("");

  delay(500);  // Wait 1 second before the next reading
}
