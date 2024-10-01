#include <WiFi.h>
#include <esp_now.h>

// Address of ESP8266
uint8_t esp8266Address[] = {0x5C, 0xCF, 0x7F, 0x1B, 0x63, 0xD5};

// Structure to receive data
typedef struct struct_message {
    char text[50];
} struct_message;

struct_message incomingData;

// Callback function that will be executed when data is received
void OnDataRecv(const uint8_t *mac_addr, const uint8_t *incomingData, int len) {
    memcpy(&incomingData, incomingData, sizeof(incomingData));
    Serial.print("Message received: ");
    Serial.println(incomingData->text);
}

void setup() {
    // Initialize Serial Monitor
    Serial.begin(115200);

    // Set device as a Wi-Fi Station
    WiFi.mode(WIFI_STA);

    // Initialize ESP-NOW
    if (esp_now_init() != ESP_OK) {
        Serial.println("Error initializing ESP-NOW");
        return;
    }

    // Register callback function to receive data
    esp_now_register_recv_cb(OnDataRecv);
}

void loop() {
    // Keep it empty for now
}
