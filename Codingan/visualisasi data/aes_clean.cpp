#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Crypto.h>
#include <AES.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
#include "PlaintextData.h"
using namespace std::chrono;

const size_t BLOCK_SIZE = 16;
const unsigned long TIMEOUT_MS = 100;
size_t totalChunks = 0;
size_t chunksAcked = 0;
bool allChunksSent = false;
bool status = false;

uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

uint8_t iv[BLOCK_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

void applyPadding(uint8_t *data, size_t len, size_t paddedLen) {
    uint8_t padValue = paddedLen - len;
    for (size_t i = len; i < paddedLen; ++i) {
        data[i] = padValue;
    }
}

void aes256CbcEncrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32], uint8_t iv[BLOCK_SIZE]) {
    AES aes;
    aes.set_key(key, 32);
    uint8_t currentIv[BLOCK_SIZE];
    memcpy(currentIv, iv, BLOCK_SIZE); 

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        for (size_t j = 0; j < BLOCK_SIZE; ++j) {
            output[i + j] = input[i + j] ^ currentIv[j];
        }
        aes.encrypt(output + i, output + i);
        memcpy(currentIv, output + i, BLOCK_SIZE);
    }
}

uint8_t* encryptMessage(const char *plaintext, size_t &encryptedLen, unsigned long &encryptionTime) {
    size_t messageLen = strlen(plaintext);
    size_t paddedLen = (messageLen + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
    encryptedLen = paddedLen;

    uint8_t *ciphertext = (uint8_t *)malloc(paddedLen);
    if (!ciphertext) {
        Serial.println("Failed to allocate encryption buffer");
        return nullptr;
    }
    memcpy(ciphertext, plaintext, messageLen);
    applyPadding(ciphertext, messageLen, paddedLen);

    auto start = high_resolution_clock::now();
    aes256CbcEncrypt(ciphertext, ciphertext, paddedLen, key, iv);
    auto end = high_resolution_clock::now();
    delay(2000);

    encryptionTime = duration_cast<microseconds>(end - start).count();

    return ciphertext;
}

bool sendEncryptedData(uint8_t *data, size_t len) {
    totalChunks = (len + 249) / 250; 
    chunksAcked = 0;
    allChunksSent = false;

    for (size_t i = 0; i < len; i += 250) {
        size_t chunkSize = min((size_t)250, len - i);
        if (esp_now_send(nullptr, data + i, chunkSize) != 0) {
            Serial.println("Error sending data");
            return false;
        }
        delay(10); 
    }
    unsigned long startTime = millis();
    while (!allChunksSent && (millis() - startTime < TIMEOUT_MS)) {
        delay(10);
    }

    return allChunksSent;
}

void onSend(uint8_t *mac_addr, uint8_t deliveryStatus) {
    if (deliveryStatus == 0) {  
        status = true;
        chunksAcked++; 
    } else {
        status = false;
    }
    if (chunksAcked == totalChunks && deliveryStatus == 0) {
        allChunksSent = true;
        Serial.println("All chunks sent successfully");
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        ESP.restart();
    }
    esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);
    esp_now_register_send_cb(onSend); 
    uint8_t receiverMac[] = {0x84, 0xF3, 0xEB, 0x05, 0x50, 0xB7};
    esp_now_add_peer(receiverMac, ESP_NOW_ROLE_SLAVE, 1, NULL, 0);
}

void loop() {
    
    size_t plaintextSize = strlen(plaintextSets[2]);
    size_t encryptedLen = 0;
    unsigned long encryptionTime = 0;

    uint8_t *ciphertext = encryptMessage(plaintextSets[2], encryptedLen, encryptionTime);

    if (ciphertext != nullptr) {
        Serial.print("Encryption Time: ");
        Serial.print(encryptionTime);
        Serial.println(" microseconds (μs)");

        Serial.print("Encrypted Data: ");
        for (size_t i = 0; i < encryptedLen; i++) {
            Serial.print(ciphertext[i], HEX); 
        }
        Serial.println(); 

        Serial.print("Plaintext Size: ");
        Serial.print(plaintextSize);
        Serial.println(" Byte (B)");
        Serial.print("Total Chunks: ");
        Serial.println(totalChunks);

        sendEncryptedData(ciphertext, encryptedLen);
        if (allChunksSent == false) {
        Serial.println("Chunks failed to send");
    };
        free(ciphertext);
    }

    delay(2000); 
    Serial.println("------------------------------------------------");
}
