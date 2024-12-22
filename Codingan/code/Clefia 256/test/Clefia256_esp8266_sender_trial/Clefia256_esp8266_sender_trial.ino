#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Arduino.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
#include "InputData.h" //plaintext, con256, s1, dan s0 ada di header ini
using namespace std::chrono;

// Configuration
const int MAX_DATA_SIZE = 16384; // 16KB
const int ESP_NOW_MAX_PAYLOAD = 240; 
const int CLEFIA_BLOCK_SIZE = 16;
const int CLEFIA_KEY_SIZE = 32;
const int CLEFIA_ROUNDS = 26;
bool status;

// Forward declarations
void clefiaEncrypt(uint32_t *ciphertext, const uint32_t *plaintext, const uint32_t *rk);
void clefiaKeySchedule(uint32_t *rk, const uint8_t *key);
void clefiaF(uint32_t *dst, const uint32_t *src, int offset);

// Transmission control
struct PacketHeader {
  uint16_t sequenceNumber;
  uint16_t totalPackets;
  uint16_t payloadSize;
};

// Global variables with memory optimization
uint8_t* dataBuffer = nullptr;
size_t currentDataSize = 0;
uint8_t* encryptionBuffer = nullptr;
uint32_t* roundKeys = nullptr;
bool transmissionInProgress = false;

// Receiver MAC address
uint8_t receiverMAC[] = {0x84, 0xF3, 0xEB, 0x05, 0x50, 0xB7};

// Helper functions
inline uint32_t rotl(uint32_t x, int s) {
    return (x << s) | (x >> (32 - s));
}

inline uint32_t rotr(uint32_t x, int s) {
    return (x >> s) | (x << (32 - s));
}

inline uint32_t pgm_read_con256(int index) {
    return pgm_read_dword(&con256[index]);
}

inline uint8_t pgm_read_S0(int index) {
    return pgm_read_byte(&S0[index]);
}

inline uint8_t pgm_read_S1(int index) {
    return pgm_read_byte(&S1[index]);
}

// Core CLEFIA Functions
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
    
    yield();
}

void ICACHE_RAM_ATTR clefiaKeySchedule(uint32_t *rk, const uint8_t *key) {
    uint32_t L[4], R[4];
    
    for (int i = 0; i < 4; i++) {
        L[i] = ((uint32_t)key[4*i+3] << 24) | 
               ((uint32_t)key[4*i+2] << 16) |
               ((uint32_t)key[4*i+1] << 8) | 
               ((uint32_t)key[4*i]);
        yield();
    }

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
        delay(2);
        yield();
    }

    for (int i = 0; i < 4; i++) {
        rk[CLEFIA_ROUNDS + i] = L[i];
    }
}

void ICACHE_RAM_ATTR clefiaEncrypt(uint32_t *ciphertext, const uint32_t *plaintext, const uint32_t *rk) {
    uint32_t L[2], R[2], T[2];
    
    L[0] = plaintext[0] ^ rk[0];
    L[1] = plaintext[1] ^ rk[1];
    R[0] = plaintext[2] ^ rk[2];
    R[1] = plaintext[3] ^ rk[3];
    
    for (int i = 0; i < CLEFIA_ROUNDS; i += 2) {
        clefiaF(T, L, i);
        T[0] ^= R[0];
        T[1] ^= R[1];
        
        memcpy(R, L, 8);
        memcpy(L, T, 8);
        
        if (i % 8 == 0) yield();
    }
    
    ciphertext[0] = L[0] ^ rk[CLEFIA_ROUNDS];
    ciphertext[1] = L[1] ^ rk[CLEFIA_ROUNDS + 1];
    ciphertext[2] = R[0] ^ rk[CLEFIA_ROUNDS + 2];
    ciphertext[3] = R[1] ^ rk[CLEFIA_ROUNDS + 3];
}

// Memory management functions
bool allocateBuffers(size_t size) {
    freeBuffers();
    
    size_t alignedSize = ((size + CLEFIA_BLOCK_SIZE - 1) / CLEFIA_BLOCK_SIZE) * CLEFIA_BLOCK_SIZE;
    
    dataBuffer = (uint8_t*)malloc(alignedSize);
    encryptionBuffer = (uint8_t*)malloc(alignedSize);
    roundKeys = (uint32_t*)malloc((CLEFIA_ROUNDS + 4) * sizeof(uint32_t));
    
    if (!dataBuffer || !encryptionBuffer || !roundKeys) {
        freeBuffers();
        return false;
    }
    
    return true;
}

void freeBuffers() {
    if (dataBuffer) {
        free(dataBuffer);
        dataBuffer = nullptr;
    }
    if (encryptionBuffer) {
        free(encryptionBuffer);
        encryptionBuffer = nullptr;
    }
    if (roundKeys) {
        free(roundKeys);
        roundKeys = nullptr;
    }
    
    ESP.wdtFeed();
    delay(0);
}

// Block encryption function
void encryptBlock(uint8_t* output, const uint8_t* input, const uint32_t* rk) {
    uint32_t block[4];
    memcpy(block, input, CLEFIA_BLOCK_SIZE);
    
    clefiaEncrypt((uint32_t*)output, block, rk);
    
    ESP.wdtFeed();
}

// Process and send data in chunks
bool processAndSendData(const uint8_t* data, size_t length) {
  if (length > MAX_DATA_SIZE || transmissionInProgress) {
    return false;
  }
  
  if (!allocateBuffers(length)) {
    Serial.println(F("Failed to allocate memory"));
    return false;
  }
  
  // Copy input data
  memcpy(dataBuffer, data, length);
  currentDataSize = length;
  
  // Pad data to block size
  size_t paddedSize = ((length + CLEFIA_BLOCK_SIZE - 1) / CLEFIA_BLOCK_SIZE) * CLEFIA_BLOCK_SIZE;
  memset(dataBuffer + length, 0, paddedSize - length);
  
  // Generate round keys
  static const uint8_t key[CLEFIA_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
  };
  

   auto encryptionStart = std::chrono::high_resolution_clock::now();
  clefiaKeySchedule(roundKeys, key); 
  // Encrypt data in blocks
  for (size_t i = 0; i < paddedSize; i += CLEFIA_BLOCK_SIZE) {
    encryptBlock(encryptionBuffer + i, dataBuffer + i, roundKeys);
    yield();
  }

  auto encryptionEnd = std::chrono::high_resolution_clock::now();
  auto encryptionDuration = std::chrono::duration_cast<std::chrono::microseconds>(encryptionEnd - encryptionStart).count();
  // Serial.print(F("Encrypted data size (bytes): "));
  // Serial.println(paddedSize);
  Serial.print(F("Encryption time (microseconds): "));
  Serial.println(encryptionDuration);

  delay(2000);
  Serial.print(F("Encrypted Data: "));
  for (size_t i = 0; i < paddedSize; i++) {
    Serial.printf("%02X", encryptionBuffer[i]); 
  }
  Serial.println(); // Final line break after the last byte
  
  // Calculate number of packets needed
  const size_t dataPerPacket = ESP_NOW_MAX_PAYLOAD - sizeof(PacketHeader);
  const uint16_t totalPackets = (paddedSize + dataPerPacket - 1) / dataPerPacket;
  Serial.print(F("Total Chunk: "));
  Serial.println(totalPackets);
  
  // Send encrypted data in chunks
  transmissionInProgress = true;
  
  for (uint16_t packet = 0; packet < totalPackets; packet++) {
    size_t offset = packet * dataPerPacket;
    size_t remainingBytes = paddedSize - offset;
    size_t payloadSize = min(dataPerPacket, remainingBytes);
    
    // Prepare packet
    uint8_t* packetBuffer = (uint8_t*)malloc(sizeof(PacketHeader) + payloadSize);
    if (!packetBuffer) {
      Serial.println(F("Packet allocation failed"));
      transmissionInProgress = false;
      return false;
    }
    
    // Fill header
    PacketHeader* header = (PacketHeader*)packetBuffer;
    header->sequenceNumber = packet;
    header->totalPackets = totalPackets;
    header->payloadSize = payloadSize;
    
    // Copy encrypted data
    memcpy(packetBuffer + sizeof(PacketHeader), 
           encryptionBuffer + offset, 
           payloadSize);
    
    // Send packet
    esp_now_send(receiverMAC, packetBuffer, sizeof(PacketHeader) + payloadSize);
    
    free(packetBuffer);
    
    // Small delay between packets
    delay(10);
    yield();
  }
  
  transmissionInProgress = false;
  freeBuffers();
  return true;
}

// ESP-NOW callback
void ICACHE_RAM_ATTR OnDataSent(uint8_t *mac_addr, uint8_t sendStatus) {
    static bool success = (sendStatus == 0);
    if (sendStatus == 0) {
    status = true;      
    }
    else if (sendStatus == 0){
        status = false;      
    }
}

void setup() {
    Serial.begin(115200);
    while (!Serial) { yield(); }
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    if (esp_now_init() != 0) {
        Serial.println(F("ESP-NOW init failed"));
        return;
    }
    
    esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);
    esp_now_register_send_cb(OnDataSent);
    esp_now_add_peer(receiverMAC, ESP_NOW_ROLE_SLAVE, 1, NULL, 0);
    
    Serial.println(F("Setup complete"));
}

void loop() {
    size_t plainTextSize = strlen(plaintextSets[2]);

    Serial.print("Size of Data: ");
    Serial.print(plainTextSize);
    Serial.println(" bytes");    
    Serial.print("Plaintext: ");
    Serial.println(plaintextSets[2]);    
    
    // Check if there’s no ongoing transmission before sending
    if (!transmissionInProgress) {
        bool success = processAndSendData((uint8_t*)plaintextSets[2], plainTextSize);
        // Print transmission status
        if (status) {
            Serial.println(F("Send successful"));
        } else if (status == false){
            Serial.println(F("Send failed"));
        }
    }
    Serial.println("------------------------------------------------");
    delay(2000); 
    yield();
}