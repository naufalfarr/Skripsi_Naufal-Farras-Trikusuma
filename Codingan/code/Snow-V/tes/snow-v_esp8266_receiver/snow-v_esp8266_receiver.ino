#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
using namespace std::chrono;

// Kunci 256-bit (32 byte), harus sama dengan yang ada di pengirim
uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// Nonce 128-bit (16 byte)
uint8_t nonce[16] = {
    0x00, 0x00, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x4A,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

// Counter, disinkronkan dengan pengirim
uint32_t counter = 1;

void initializeSnowV(uint32_t *LFSR, uint32_t *FSM, const uint8_t *key, const uint8_t *nonce) {
    for (int i = 0; i < 8; i++) {
        LFSR[i] = ((uint32_t *)key)[i];
    }
    for (int i = 8; i < 12; i++) {
        LFSR[i] = ((uint32_t *)nonce)[i - 8];
    }
    FSM[0] = FSM[1] = FSM[2] = 0;
}

void generateSnowVKeystream(uint32_t *LFSR, uint32_t *FSM, uint8_t *keystream, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t f = (FSM[0] + LFSR[0]) ^ FSM[2];
        
        FSM[2] = FSM[1];
        FSM[1] = FSM[0];
        FSM[0] = f;

        uint32_t s = LFSR[11];
        for (int j = 11; j > 0; j--) {
            LFSR[j] = LFSR[j-1];
        }
        LFSR[0] = s ^ f;

        ((uint32_t *)keystream)[i / 4] = f;
    }
}

void snowVEncryptDecrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32], const uint8_t nonce[16], uint32_t counter) {
    uint32_t LFSR[12], FSM[3];
    
    initializeSnowV(LFSR, FSM, key, nonce);
    
    uint8_t keystream[64];
    size_t i = 0;

    while (i < len) {
        generateSnowVKeystream(LFSR, FSM, keystream, 64);
        for (size_t j = 0; j < 64 && i < len; ++j, ++i) {
            output[i] = input[i] ^ keystream[j];
        }
    }
}

void onReceive(uint8_t *mac, uint8_t *incomingData, uint8_t len) {
    uint8_t decryptedData[len];

    
    auto start = high_resolution_clock::now();
    // Dekripsi data yang diterima
    snowVEncryptDecrypt(incomingData, decryptedData, len, key, nonce, counter);
    auto end = high_resolution_clock::now();

    // Hitung durasi enkripsi
    auto decryptDuration = duration_cast<microseconds>(end - start).count();

    // Tampilkan hasil dekripsi sebagai plaintext
    Serial.print("Decrypted Message: ");
    for (int i = 0; i < len; i++) {
        Serial.print((char)decryptedData[i]);
    }
    Serial.println();
    Serial.print("Encryption Time Computation: ");
    Serial.print(decryptDuration);
    Serial.println(" mikrosecond (μs)");  
}

void setup() {
    Serial.begin(115200);

    WiFi.mode(WIFI_STA);

    if (esp_now_init() != 0) {
        Serial.println("ESP-NOW initialization failed");
        return;
    }

    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE); // Set sebagai penerima
    esp_now_register_recv_cb(onReceive);

    Serial.println("Receiver is ready");
}

void loop() {
  delay(100);
    // Tidak perlu melakukan apa-apa di loop, semua ditangani oleh callback
}
