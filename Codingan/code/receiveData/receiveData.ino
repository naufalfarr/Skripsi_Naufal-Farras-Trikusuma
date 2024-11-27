#include <ESP8266WiFi.h>
#include <espnow.h>
#include <SD.h>

// Globals for received data
uint8_t *receivedData = nullptr;
size_t totalDataLen = 0;
bool allFragmentsReceived = false;
int fileIndex = 0; // File index for saving received data

// ESP-NOW data reception
void onDataRecv(uint8_t *mac_addr, uint8_t *incomingData, uint8_t len) {
    uint8_t fragmentNum = incomingData[0];
    bool isLast = incomingData[1];

    if (fragmentNum == 0) {
        if (receivedData != nullptr) {
            free(receivedData);
        }
        receivedData = (uint8_t *)malloc(15360); // Allocate enough memory for large data
        if (receivedData == nullptr) {
            Serial.println("Memory allocation failed!");
            return;
        }
        totalDataLen = 0;
    }

    if (receivedData != nullptr) {
        memcpy(receivedData + (fragmentNum * 240), incomingData + 2, len - 2);
        totalDataLen += (len - 2);

        if (isLast) {
            allFragmentsReceived = true;
        }
    }

    // Print received fragment data
    Serial.print("Encrypted Data Received: ");
    Serial.write(incomingData + 2, len - 2); // Skip metadata
    Serial.println();
}

// Save received data to SD card
bool saveReceivedDataToSD(const uint8_t *data, size_t dataLen) {
    String filename = "/received_data_" + String(fileIndex) + ".txt";
    File dataFile = SD.open(filename, FILE_WRITE);

    if (!dataFile) {
        Serial.println("Error opening file for writing");
        return false;
    }

    size_t bytesWritten = dataFile.write(data, dataLen);
    dataFile.close();

    if (bytesWritten != dataLen) {
        Serial.println("Error writing to file");
        return false;
    }

    // Serial.print("Data saved to ");
    // Serial.println(filename);

    fileIndex++;
    return true;
}

// Process received messages
void processReceivedMessage() {
    if (!allFragmentsReceived || receivedData == nullptr) {
        return;
    }
    if (!saveReceivedDataToSD(receivedData, totalDataLen)) {
        Serial.println("Failed to save data to SD card");
    }

    // Free the memory after processing
    free(receivedData);
    receivedData = nullptr;
    totalDataLen = 0;
    allFragmentsReceived = false;

    // Serial.println("Data processing complete and memory freed.");
    // Serial.println("------------------------------------------------");
}

// ESP-NOW initialization
bool initESPNow() {
    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_register_recv_cb(onDataRecv);
    return true;
}

// Arduino setup
void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (!SD.begin(D8)) { // Initialize SD card on D8 pin
        Serial.println("SD card initialization failed!");
        return;
    }

    if (!initESPNow()) {
        Serial.println("ESP-NOW initialization failed");
        return;
    }

    Serial.println("Setup complete. Waiting for ESP-NOW data...");
}

void loop() {
    processReceivedMessage();
    delay(50); // Small delay to prevent excessive CPU usage
}
