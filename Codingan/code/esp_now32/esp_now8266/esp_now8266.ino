#include <ESP8266WiFi.h> 

void setup() {
  Serial.begin(115200);  // Memulai komunikasi serial
  // Mendapatkan dan menampilkan MAC address
  Serial.print("MAC Address: ");
  Serial.println(WiFi.macAddress());
}

void loop() {
  Serial.print("MAC Address: ");
  Serial.println(WiFi.macAddress());
  delay(5000);
  
  // Tidak ada loop yang diperlukan
}
