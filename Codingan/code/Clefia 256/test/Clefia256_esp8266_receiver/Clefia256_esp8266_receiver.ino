#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Arduino.h>
#include <cstring>
#include <stdint.h>
#include <SPI.h>
#include <SD.h>

// Configuration constants
const uint16_t CLEFIA_BLOCK_SIZE = 16;
const uint16_t CLEFIA_KEY_SIZE = 32;
const uint16_t CLEFIA_ROUNDS = 32;
const uint16_t MAX_PACKET_SIZE = 250; 

// Static memory allocation for frequently used buffers
struct DecryptionContext {
    uint32_t roundKeys[CLEFIA_ROUNDS + 4]; // +4 for the final round keys
    uint8_t decryptBuffer[CLEFIA_BLOCK_SIZE];
    uint32_t tempBuffer[CLEFIA_BLOCK_SIZE / sizeof(uint32_t)];
    bool isInitialized;
} static_ctx;

// Packet structure with fixed size
struct __attribute__((packed)) PacketHeader {
    uint16_t sequenceNumber;
    uint16_t totalPackets;
    uint16_t payloadSize;
};

// SD card configuration
const int chipSelect = D8; // Pin chip select untuk microSD
uint32_t fileIndex = 0;    // Indeks file untuk membuat nama file unik

// Forward declarations
void clefiaDecrypt(uint32_t* plaintext, const uint32_t* ciphertext, const uint32_t* rk);
void clefiaKeySchedule(uint32_t* rk, const uint8_t* key);
void clefiaF(uint32_t* dst, const uint32_t* src, int offset);

// Move constant tables to PROGMEM
#include "clefia_constants.h" // Contains S0, S1, and con256 arrays

// Helper functions
ICACHE_RAM_ATTR inline uint32_t rotl(uint32_t x, int s) {
    return (x << s) | (x >> (32 - s));
}

ICACHE_RAM_ATTR inline uint32_t rotr(uint32_t x, int s) {
    return (x >> s) | (x << (32 - s));
}

void initializeDecryptionContext() {
    if (!static_ctx.isInitialized) {
        static const uint8_t key[CLEFIA_KEY_SIZE] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
        };
        clefiaKeySchedule(static_ctx.roundKeys, key);
        static_ctx.isInitialized = true;
    }
}

void clefiaDecrypt(uint32_t* plaintext, const uint32_t* ciphertext, const uint32_t* rk) {
    memcpy(static_ctx.tempBuffer, ciphertext, CLEFIA_BLOCK_SIZE);

    for (int i = CLEFIA_ROUNDS - 1; i >= 0; i--) {
        clefiaF(static_ctx.tempBuffer, rk + i * 2, i);
    }

    memcpy(plaintext, static_ctx.tempBuffer, CLEFIA_BLOCK_SIZE);
}

// Save decrypted data to SD card
bool saveDecryptedDataToSD(uint8_t* plaintext, size_t dataLen) {
    // Generate filename with sequential index
    String filename = "/clefia_decrypted_" + String(fileIndex++) + ".txt";

    // Open file for writing
    File dataFile = SD.open(filename, FILE_WRITE);

    if (!dataFile) {
        Serial.println("Error opening file for writing");
        return false;
    }

    // Write data to file
    for (size_t i = 0; i < dataLen; i++) {
        if (plaintext[i] < 0x10) {
            dataFile.print("0");
        }
        dataFile.print(plaintext[i], HEX);
        dataFile.print(" ");
    }

    dataFile.close();
    Serial.print("Decrypted data saved to: ");
    Serial.println(filename);
    return true;
}

// ESP-NOW callback for receiving data
void onDataReceive(uint8_t* mac, uint8_t* incomingData, uint8_t len) {
    if (len < sizeof(PacketHeader) || len > MAX_PACKET_SIZE) {
        Serial.println(F("Invalid packet size"));
        return;
    }

    PacketHeader header;
    memcpy(&header, incomingData, sizeof(PacketHeader));

    if (header.payloadSize > CLEFIA_BLOCK_SIZE || 
        sizeof(PacketHeader) + header.payloadSize > len) {
        Serial.println(F("Invalid payload size"));
        return;
    }

    uint32_t* decryptedData = (uint32_t*)static_ctx.decryptBuffer;
    const uint32_t* encryptedData = (uint32_t*)(incomingData + sizeof(PacketHeader));

    clefiaDecrypt(decryptedData, encryptedData, static_ctx.roundKeys);

    Serial.print(F("Decrypted data: "));
    for (uint16_t i = 0; i < header.payloadSize; i++) {
        if (static_ctx.decryptBuffer[i] < 0x10) Serial.print(F("0"));
        Serial.print(static_ctx.decryptBuffer[i], HEX);
        Serial.print(F(" "));
    }
    Serial.println();

    saveDecryptedDataToSD(static_ctx.decryptBuffer, header.payloadSize);
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    if (!SD.begin(chipSelect)) {
        Serial.println("SD card initialization failed!");
        return;
    }
    Serial.println("SD card initialized.");

    memset(&static_ctx, 0, sizeof(DecryptionContext));
    initializeDecryptionContext();

    if (esp_now_init() == 0) {
        esp_now_register_recv_cb(onDataReceive);
        Serial.println(F("ESP-NOW initialized"));
    } else {
        Serial.println(F("ESP-NOW initialization failed"));
    }
}

void loop() {
    yield(); 
}