#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Arduino.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
using namespace std::chrono;

// Configuration
const int MAX_DATA_SIZE = 16384; // 16KB
const int ESP_NOW_MAX_PAYLOAD = 250; // ESP-NOW max packet size
const int CLEFIA_BLOCK_SIZE = 16;
const int CLEFIA_KEY_SIZE = 32;
const int CLEFIA_ROUNDS = 32;
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

// CLEFIA Constants in PROGMEM
const PROGMEM uint32_t con256[60] = {
    0xf56b7aeb, 0x994a8a42, 0x96a4bd75, 0xfa854521,
    0x735b768a, 0x1f7abac4, 0xd5bc3b45, 0xb99d5d62,
    0x52d73592, 0x3ef636e5, 0xc57a1ac9, 0xa95b9b72,
    0x5ab42554, 0x369555ed, 0x1553ba9a, 0x7972b2a2,
    0xe6b85d4d, 0x8a995951, 0x4b550696, 0x2774b4fc,
    0xc9bb034b, 0xa59a5a7e, 0x88cc81a5, 0xe4ed2d3f,
    0x7c6f68e2, 0x104e8ecb, 0xd2263471, 0xbe07c765,
    0x511a3208, 0x3d3bfbe6, 0x1084b134, 0x7ca565a7,
    0x304bf0aa, 0x5c6aaa87, 0xf4347855, 0x9815d543,
    0x4213141a, 0x2e32f2f5, 0xcd180a0d, 0xa139f97a,
    0x5e852d36, 0x32a464e9, 0xc353169b, 0xaf72b274,
    0x8db88b4d, 0xe199593a, 0x7ed56d96, 0x12f434c9,
    0xd37b36cb, 0xbf5a9a64, 0x85ac9b65, 0xe98d4d32,
    0x7adf6582, 0x16fe3ecd, 0xd17e32c1, 0xbd5f9f66,
    0x50b63150, 0x3c9757e7, 0x1052b098, 0x7c73b3a7
};

const PROGMEM uint8_t S0[256] = {
  0x57U, 0x49U, 0xd1U, 0xc6U, 0x2fU, 0x33U, 0x74U, 0xfbU,
  0x95U, 0x6dU, 0x82U, 0xeaU, 0x0eU, 0xb0U, 0xa8U, 0x1cU,
  0x28U, 0xd0U, 0x4bU, 0x92U, 0x5cU, 0xeeU, 0x85U, 0xb1U,
  0xc4U, 0x0aU, 0x76U, 0x3dU, 0x63U, 0xf9U, 0x17U, 0xafU,
  0xbfU, 0xa1U, 0x19U, 0x65U, 0xf7U, 0x7aU, 0x32U, 0x20U,
  0x06U, 0xceU, 0xe4U, 0x83U, 0x9dU, 0x5bU, 0x4cU, 0xd8U,
  0x42U, 0x5dU, 0x2eU, 0xe8U, 0xd4U, 0x9bU, 0x0fU, 0x13U,
  0x3cU, 0x89U, 0x67U, 0xc0U, 0x71U, 0xaaU, 0xb6U, 0xf5U,
  0xa4U, 0xbeU, 0xfdU, 0x8cU, 0x12U, 0x00U, 0x97U, 0xdaU,
  0x78U, 0xe1U, 0xcfU, 0x6bU, 0x39U, 0x43U, 0x55U, 0x26U,
  0x30U, 0x98U, 0xccU, 0xddU, 0xebU, 0x54U, 0xb3U, 0x8fU,
  0x4eU, 0x16U, 0xfaU, 0x22U, 0xa5U, 0x77U, 0x09U, 0x61U,
  0xd6U, 0x2aU, 0x53U, 0x37U, 0x45U, 0xc1U, 0x6cU, 0xaeU,
  0xefU, 0x70U, 0x08U, 0x99U, 0x8bU, 0x1dU, 0xf2U, 0xb4U,
  0xe9U, 0xc7U, 0x9fU, 0x4aU, 0x31U, 0x25U, 0xfeU, 0x7cU,
  0xd3U, 0xa2U, 0xbdU, 0x56U, 0x14U, 0x88U, 0x60U, 0x0bU,
  0xcdU, 0xe2U, 0x34U, 0x50U, 0x9eU, 0xdcU, 0x11U, 0x05U,
  0x2bU, 0xb7U, 0xa9U, 0x48U, 0xffU, 0x66U, 0x8aU, 0x73U,
  0x03U, 0x75U, 0x86U, 0xf1U, 0x6aU, 0xa7U, 0x40U, 0xc2U,
  0xb9U, 0x2cU, 0xdbU, 0x1fU, 0x58U, 0x94U, 0x3eU, 0xedU,
  0xfcU, 0x1bU, 0xa0U, 0x04U, 0xb8U, 0x8dU, 0xe6U, 0x59U,
  0x62U, 0x93U, 0x35U, 0x7eU, 0xcaU, 0x21U, 0xdfU, 0x47U,
  0x15U, 0xf3U, 0xbaU, 0x7fU, 0xa6U, 0x69U, 0xc8U, 0x4dU,
  0x87U, 0x3bU, 0x9cU, 0x01U, 0xe0U, 0xdeU, 0x24U, 0x52U,
  0x7bU, 0x0cU, 0x68U, 0x1eU, 0x80U, 0xb2U, 0x5aU, 0xe7U,
  0xadU, 0xd5U, 0x23U, 0xf4U, 0x46U, 0x3fU, 0x91U, 0xc9U,
  0x6eU, 0x84U, 0x72U, 0xbbU, 0x0dU, 0x18U, 0xd9U, 0x96U,
  0xf0U, 0x5fU, 0x41U, 0xacU, 0x27U, 0xc5U, 0xe3U, 0x3aU,
  0x81U, 0x6fU, 0x07U, 0xa3U, 0x79U, 0xf6U, 0x2dU, 0x38U,
  0x1aU, 0x44U, 0x5eU, 0xb5U, 0xd2U, 0xecU, 0xcbU, 0x90U,
  0x9aU, 0x36U, 0xe5U, 0x29U, 0xc3U, 0x4fU, 0xabU, 0x64U,
  0x51U, 0xf8U, 0x10U, 0xd7U, 0xbcU, 0x02U, 0x7dU, 0x8eU
  };

const PROGMEM uint8_t S1[256] = {
  0x6cU, 0xdaU, 0xc3U, 0xe9U, 0x4eU, 0x9dU, 0x0aU, 0x3dU,
  0xb8U, 0x36U, 0xb4U, 0x38U, 0x13U, 0x34U, 0x0cU, 0xd9U,
  0xbfU, 0x74U, 0x94U, 0x8fU, 0xb7U, 0x9cU, 0xe5U, 0xdcU,
  0x9eU, 0x07U, 0x49U, 0x4fU, 0x98U, 0x2cU, 0xb0U, 0x93U,
  0x12U, 0xebU, 0xcdU, 0xb3U, 0x92U, 0xe7U, 0x41U, 0x60U,
  0xe3U, 0x21U, 0x27U, 0x3bU, 0xe6U, 0x19U, 0xd2U, 0x0eU,
  0x91U, 0x11U, 0xc7U, 0x3fU, 0x2aU, 0x8eU, 0xa1U, 0xbcU,
  0x2bU, 0xc8U, 0xc5U, 0x0fU, 0x5bU, 0xf3U, 0x87U, 0x8bU,
  0xfbU, 0xf5U, 0xdeU, 0x20U, 0xc6U, 0xa7U, 0x84U, 0xceU,
  0xd8U, 0x65U, 0x51U, 0xc9U, 0xa4U, 0xefU, 0x43U, 0x53U,
  0x25U, 0x5dU, 0x9bU, 0x31U, 0xe8U, 0x3eU, 0x0dU, 0xd7U,
  0x80U, 0xffU, 0x69U, 0x8aU, 0xbaU, 0x0bU, 0x73U, 0x5cU,
  0x6eU, 0x54U, 0x15U, 0x62U, 0xf6U, 0x35U, 0x30U, 0x52U,
  0xa3U, 0x16U, 0xd3U, 0x28U, 0x32U, 0xfaU, 0xaaU, 0x5eU,
  0xcfU, 0xeaU, 0xedU, 0x78U, 0x33U, 0x58U, 0x09U, 0x7bU,
  0x63U, 0xc0U, 0xc1U, 0x46U, 0x1eU, 0xdfU, 0xa9U, 0x99U,
  0x55U, 0x04U, 0xc4U, 0x86U, 0x39U, 0x77U, 0x82U, 0xecU,
  0x40U, 0x18U, 0x90U, 0x97U, 0x59U, 0xddU, 0x83U, 0x1fU,
  0x9aU, 0x37U, 0x06U, 0x24U, 0x64U, 0x7cU, 0xa5U, 0x56U,
  0x48U, 0x08U, 0x85U, 0xd0U, 0x61U, 0x26U, 0xcaU, 0x6fU,
  0x7eU, 0x6aU, 0xb6U, 0x71U, 0xa0U, 0x70U, 0x05U, 0xd1U,
  0x45U, 0x8cU, 0x23U, 0x1cU, 0xf0U, 0xeeU, 0x89U, 0xadU,
  0x7aU, 0x4bU, 0xc2U, 0x2fU, 0xdbU, 0x5aU, 0x4dU, 0x76U,
  0x67U, 0x17U, 0x2dU, 0xf4U, 0xcbU, 0xb1U, 0x4aU, 0xa8U,
  0xb5U, 0x22U, 0x47U, 0x3aU, 0xd5U, 0x10U, 0x4cU, 0x72U,
  0xccU, 0x00U, 0xf9U, 0xe0U, 0xfdU, 0xe2U, 0xfeU, 0xaeU,
  0xf8U, 0x5fU, 0xabU, 0xf1U, 0x1bU, 0x42U, 0x81U, 0xd6U,
  0xbeU, 0x44U, 0x29U, 0xa6U, 0x57U, 0xb9U, 0xafU, 0xf2U,
  0xd4U, 0x75U, 0x66U, 0xbbU, 0x68U, 0x9fU, 0x50U, 0x02U,
  0x01U, 0x3cU, 0x7fU, 0x8dU, 0x1aU, 0x88U, 0xbdU, 0xacU,
  0xf7U, 0xe4U, 0x79U, 0x96U, 0xa2U, 0xfcU, 0x6dU, 0xb2U,
  0x6bU, 0x03U, 0xe1U, 0x2eU, 0x7dU, 0x14U, 0x95U, 0x1dU
  };

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
  
  clefiaKeySchedule(roundKeys, key); 

   auto encryptionStart = std::chrono::high_resolution_clock::now();
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
    // Example: encrypt and send a message
    const char* message =       
      "30.80,73.80"
      "30.80,73.80"
      "dataEnd";
    size_t messageSize = strlen(message);
    
    // Print plain text and its size
    Serial.print("Original Data Size: ");
    Serial.print(messageSize);
    Serial.println(" Byte (B)");
    
    // Check if there’s no ongoing transmission before sending
    if (!transmissionInProgress) {
        bool success = processAndSendData((uint8_t*)message, messageSize);
        
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