#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Crypto.h>
#include <AES.h>
#include <cstring>
#include <stdint.h>
#include <chrono>

using namespace std::chrono;

const size_t BLOCK_SIZE = 16;
const unsigned long TIMEOUT_MS = 100; // Timeout of 100 ms for receiving data chunks
const uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

uint8_t *receivedData = nullptr; // Pointer to dynamically allocated buffer
size_t receivedLen = 0;          // Current size of received data
size_t bufferSize = 0;           // Current allocated size of buffer
unsigned long lastReceivedTime = 0; // Time of last received data

// AES-256 ECB Decryption
void aes256Decrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32]) {
    AES aes;
    aes.set_key(key, 32);
    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        aes.decrypt(input + i, output + i);
    }
}

// Remove PKCS7 padding
size_t removePadding(uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint8_t padValue = data[len - 1];
    if (padValue > BLOCK_SIZE || padValue == 0) return len; // Invalid padding
    return len - padValue;
}

// Function to dynamically expand the buffer as needed
bool expandBuffer(size_t additionalSize) {
    size_t newSize = receivedLen + additionalSize;
    if (newSize > bufferSize) {
        bufferSize = newSize;
        uint8_t *newBuffer = (uint8_t *)realloc(receivedData, bufferSize);
        if (!newBuffer) {
            Serial.println("Failed to allocate memory!");
            free(receivedData);
            ESP.restart(); // Restart if memory allocation fails
            return false;
        }
        receivedData = newBuffer;
    }
    return true;
}

// Callback function to receive data
void onDataReceive(uint8_t *mac, uint8_t *incomingData, uint8_t len) {
    lastReceivedTime = millis(); // Update the last received time

    // Expand buffer to accommodate new data
    if (!expandBuffer(len)) return;

    // Copy incoming data to the buffer
    memcpy(receivedData + receivedLen, incomingData, len);
    receivedLen += len;
}

// Function to process and decrypt the data once timeout is reached
void processData() {
    if (receivedLen == 0) return; // No data to process

    Serial.println("Processing full data after timeout.");

    // Allocate buffer for decrypted data
    uint8_t *decryptedData = (uint8_t *)malloc(receivedLen);
    if (!decryptedData) {
        Serial.println("Failed to allocate decryption buffer");
        ESP.restart(); // Restart if memory allocation fails
        return;
    }

    auto start = high_resolution_clock::now();
    // Decrypt the received data
    aes256Decrypt(receivedData, decryptedData, receivedLen, key);
    auto end = high_resolution_clock::now();
    auto encryptDuration = duration_cast<microseconds>(end - start).count();  
    Serial.print("Decryption Time Computation: ");
    Serial.print(encryptDuration);
    Serial.println(" microseconds (μs)");

    // Remove padding
    size_t decryptedLen = removePadding(decryptedData, receivedLen);

    
    // Print decrypted message
    Serial.println("Decrypted Data:");
    for (size_t i = 0; i < decryptedLen; i++) {
        Serial.print((char)decryptedData[i]);
    }
    Serial.println();

    // Cleanup
    free(decryptedData);
    free(receivedData);
    receivedData = nullptr; // Reset pointer for next message
    receivedLen = 0;
    bufferSize = 0;
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        ESP.restart();
    }

    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);

    // Register the receive callback
    esp_now_register_recv_cb(onDataReceive);
}

void loop() {
    // Check for timeout: process data if no data is received for 100 ms
    if (millis() - lastReceivedTime > TIMEOUT_MS && receivedLen > 0) {
        processData();
        Serial.println("------------------------------------------------");        
    }
}
