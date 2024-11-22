#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Arduino.h>
#include <cstring>
#include <stdint.h>

// Configuration constants
const uint16_t CLEFIA_BLOCK_SIZE = 16;
const uint16_t CLEFIA_KEY_SIZE = 32;
const uint16_t CLEFIA_ROUNDS = 32;
const uint16_t MAX_PACKET_SIZE = 250; // ESP-NOW maximum packet size

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

// Forward declarations
void clefiaDecrypt(uint32_t* plaintext, const uint32_t* ciphertext, const uint32_t* rk);
void clefiaKeySchedule(uint32_t* rk, const uint8_t* key);
void clefiaF(uint32_t* dst, const uint32_t* src, int offset);

// Move constant tables to PROGMEM
#include "clefia_constants.h" // Contains S0, S1, and con256 arrays

// Helper functions with ICACHE_RAM_ATTR for interrupt context
ICACHE_RAM_ATTR inline uint32_t rotl(uint32_t x, int s) {
    return (x << s) | (x >> (32 - s));
}

ICACHE_RAM_ATTR inline uint32_t rotr(uint32_t x, int s) {
    return (x >> s) | (x << (32 - s));
}

// Optimized PROGMEM read functions
ICACHE_RAM_ATTR inline uint32_t pgm_read_con256(int index) {
    return pgm_read_dword(&con256[index]);
}

ICACHE_RAM_ATTR inline uint8_t pgm_read_S0(int index) {
    return pgm_read_byte(&S0[index]);
}

ICACHE_RAM_ATTR inline uint8_t pgm_read_S1(int index) {
    return pgm_read_byte(&S1[index]);
}

// Modified CLEFIA functions to use static context
void ICACHE_RAM_ATTR clefiaF(uint32_t *dst, const uint32_t *src, int offset) {
    uint32_t x = src[0] ^ pgm_read_con256(offset);
    uint32_t y = src[1];
    uint32_t z = pgm_read_con256(offset);

    y ^= rotr(x, 8) ^ rotl(x, 16) ^ rotl(x, 24);
    
    uint32_t temp = 0;
    temp |= ((uint32_t)pgm_read_S0((uint8_t)(y >> 24))) << 0;
    temp |= ((uint32_t)pgm_read_S1((uint8_t)(y >> 16))) << 8;
    temp |= ((uint32_t)pgm_read_S0((uint8_t)(y >> 8))) << 16;
    temp |= ((uint32_t)pgm_read_S1((uint8_t)y)) << 24;
    
    dst[0] = temp ^ z;
    dst[1] = y;
}

void initializeDecryptionContext() {
    if (!static_ctx.isInitialized) {
        // Initialize with fixed key
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

void ICACHE_RAM_ATTR clefiaKeySchedule(uint32_t *rk, const uint8_t *key) {
    uint32_t L[4], R[4];
    
    // Load key into temporary arrays
    for (int i = 0; i < 4; i++) {
        L[i] = ((uint32_t)key[4*i+3] << 24) | 
               ((uint32_t)key[4*i+2] << 16) |
               ((uint32_t)key[4*i+1] << 8) | 
               ((uint32_t)key[4*i]);
    }

    // Key schedule computation
    for (int i = 0; i < CLEFIA_ROUNDS / 4; i++) {
        memcpy(R, L, 16);
        
        clefiaF(&R[0], &R[2], i*4);
        clefiaF(&R[2], &R[0], i*4+2);
        
        for (int j = 0; j < 4; j++) {
            rk[i*4 + j] = R[j];
        }
        
        if (i % 2 == 0) {
            for (int j = 0; j < 4; j++) {
                L[j] ^= rotl(R[j], 15);
            }
        } else {
            for (int j = 0; j < 4; j++) {
                L[j] ^= rotl(R[j], 17);
            }
        }
    }

    // Store final round keys
    for (int i = 0; i < 4; i++) {
        rk[CLEFIA_ROUNDS + i] = L[i];
    }
}

void ICACHE_RAM_ATTR clefiaDecrypt(uint32_t* plaintext, const uint32_t* ciphertext, const uint32_t* rk) {
    // Use static context's temp buffer
    memcpy(static_ctx.tempBuffer, ciphertext, CLEFIA_BLOCK_SIZE);

    for (int i = CLEFIA_ROUNDS - 1; i >= 0; i--) {
        clefiaF(static_ctx.tempBuffer, rk + i * 2, i);
    }
    
    memcpy(plaintext, static_ctx.tempBuffer, CLEFIA_BLOCK_SIZE);
}

// Modified callback function with proper memory handling
void ICACHE_RAM_ATTR onDataReceive(uint8_t* mac, uint8_t* incomingData, uint8_t len) {
    if (len < sizeof(PacketHeader) || len > MAX_PACKET_SIZE) {
        Serial.println(F("Invalid packet size"));
        return;
    }

    PacketHeader header;
    memcpy(&header, incomingData, sizeof(PacketHeader));
    // Serial.print(F("Header payload size: "));
    // Serial.println(header.payloadSize);
    // Serial.print(F("Received length: "));
    // Serial.println(len);


    // Verify payload size
    if (header.payloadSize > CLEFIA_BLOCK_SIZE || 
        sizeof(PacketHeader) + header.payloadSize > len) {
        Serial.println(F("Invalid payload size"));
        return;
    }

    // Decrypt data using static buffers
    uint32_t* decryptedData = (uint32_t*)static_ctx.decryptBuffer;
    const uint32_t* encryptedData = (uint32_t*)(incomingData + sizeof(PacketHeader));
    
    clefiaDecrypt(decryptedData, encryptedData, static_ctx.roundKeys);

    // Process decrypted data
    Serial.print(F("Decrypted data: "));
    for (uint16_t i = 0; i < header.payloadSize; i++) {
        if (static_ctx.decryptBuffer[i] < 0x10) Serial.print(F("0"));
        Serial.print(static_ctx.decryptBuffer[i], HEX);
        Serial.print(F(" "));
    }
    Serial.println();
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    // Initialize static context
    memset(&static_ctx, 0, sizeof(DecryptionContext));
    initializeDecryptionContext();

    // Initialize ESP-NOW
    if (esp_now_init() == 0) {
        esp_now_register_recv_cb(onDataReceive);
        Serial.println(F("ESP-NOW initialized"));
    } else {
        Serial.println(F("ESP-NOW initialization failed"));
    }
}

void loop() {
    // Main loop remains empty as processing is handled in callback
    yield();
}