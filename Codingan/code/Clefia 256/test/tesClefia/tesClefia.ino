#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
#include "InputData.h" // file ini mencakup plaintextSets, clefia_s0, clefia_s1, dan CLEFIA_CONSTANTS
using namespace std::chrono;

// Konfigurasi CLEFIA
const int CLEFIA_BLOCK_SIZE = 16;
const int CLEFIA_KEY_SIZE = 32;
const int CLEFIA_ROUNDS = 26;

// Konfigurasi ESP-NOW
const int ESP_NOW_MAX_PAYLOAD = 250;
bool transmissionInProgress = false;

// Alamat MAC penerima
uint8_t receiverMAC[] = {0x84, 0xF3, 0xEB, 0x05, 0x50, 0xB7};

// Definisi ekstern untuk tabel S dan konstanta
extern const uint8_t clefia_s0[256];
extern const uint8_t clefia_s1[256];
extern const uint32_t CLEFIA_CONSTANTS[];

// Fungsi utility CLEFIA (tidak ada perubahan)
inline uint8_t ClefiaMul2(uint8_t x) { return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1); }

// ... (ClefiaMul4, ClefiaMul6, ClefiaMul8, ClefiaMulA sama seperti sebelumnya)

// Fungsi CLEFIA F0 dan F1 (tidak ada perubahan)
void ICACHE_RAM_ATTR clefiaF0(uint8_t *dst, const uint8_t *src, const uint8_t *rk);
void ICACHE_RAM_ATTR clefiaF1(uint8_t *dst, const uint8_t *src, const uint8_t *rk);

// Fungsi CLEFIA utama (DIPERBAIKI)
void ICACHE_RAM_ATTR clefiaEncrypt(uint8_t *ciphertext, const uint8_t *plaintext, const uint32_t *rk) {
    uint8_t state[16];
    memcpy(state, plaintext, 16);

    // Initial key whitening (DIPERBAIKI)
    for (int i = 0; i < 4; i++) {
        state[i] ^= (rk[0] >> (24 - i * 8)) & 0xFF;
        state[12 + i] ^= (rk[1] >> (24 - i * 8)) & 0xFF;
    }

    for (int i = 0; i < CLEFIA_ROUNDS; i++) {
        uint8_t temp[8];
        if (i % 2 == 0) clefiaF0(temp, state, (uint8_t*)(rk + 2 + i * 2));
        else clefiaF1(temp, state, (uint8_t*)(rk + 2 + i * 2));

        // State update (DIPERBAIKI)
        for (int j = 0; j < 8; j++){
            state[8 + j] ^= temp[j];
        }
        memmove(state, state+8, 8);
        memcpy(state+8, temp, 8);

        yield();
    }

    // Final key whitening (DIPERBAIKI)
    memcpy(ciphertext, state, 16);
    for (int i = 0; i < 4; i++) {
        ciphertext[i] ^= (rk[CLEFIA_ROUNDS * 2 + 2] >> (24 - i * 8)) & 0xFF;
        ciphertext[12 + i] ^= (rk[CLEFIA_ROUNDS * 2 + 3] >> (24 - i * 8)) & 0xFF;
    }
}

// Fungsi key schedule (tidak ada perubahan signifikan)
void clefiaKeySchedule(uint32_t *rk, const uint8_t *key);

// Fungsi pengiriman data menggunakan ESP-NOW
void sendData(const uint8_t *data, size_t length) {
    size_t paddedSize = ((length + CLEFIA_BLOCK_SIZE - 1) / CLEFIA_BLOCK_SIZE) * CLEFIA_BLOCK_SIZE;
    uint8_t encryptionBuffer[paddedSize];
    uint32_t roundKeys[CLEFIA_ROUNDS + 4];
    uint8_t key[CLEFIA_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    clefiaKeySchedule(roundKeys, key);

    memset(encryptionBuffer, 0, paddedSize); // Inisialisasi buffer enkripsi

    for (size_t i = 0; i < paddedSize; i += CLEFIA_BLOCK_SIZE) {
        clefiaEncrypt(encryptionBuffer + i, data + i, roundKeys);
    }

    size_t totalPackets = (paddedSize + ESP_NOW_MAX_PAYLOAD - 1) / ESP_NOW_MAX_PAYLOAD;
    for (size_t i = 0; i < totalPackets; i++) {
        size_t offset = i * ESP_NOW_MAX_PAYLOAD;
        size_t payloadSize = min((int)ESP_NOW_MAX_PAYLOAD, (int)(paddedSize - offset));
        esp_now_send(receiverMAC, encryptionBuffer + offset, payloadSize);
        yield(); // Penting untuk ESP8266
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        return;
    }
    esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);
    if (esp_now_add_peer(receiverMAC, ESP_NOW_ROLE_SLAVE, 1, nullptr, 0) != 0) {
        Serial.println("Error adding peer");
        return;
    }
    Serial.println(F("Setup complete."));
}

void loop() {
    if (!transmissionInProgress) {
        transmissionInProgress = true;
        sendData((uint8_t *)plaintextSets[0], strlen(plaintextSets[0]));
        transmissionInProgress = false;
    }
    delay(5000);
}