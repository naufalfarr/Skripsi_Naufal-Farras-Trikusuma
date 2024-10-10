#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
using namespace std::chrono;

// Key 256-bit (32 byte)
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

// Fungsi rotasi ke kiri (circular shift)
uint32_t rotate_left(uint32_t value, unsigned int count) {
    return (value << count) | (value >> (32 - count));
}

// Multiplikasi di GF(2^32)
uint32_t gf_mult(uint32_t a, uint32_t b) {
    uint32_t result = 0;
    for (int i = 0; i < 32; ++i) {
        if (b & 1) result ^= a;
        bool carry = a & 0x80000000;
        a <<= 1;
        if (carry) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

// Inisialisasi LFSR dengan key scheduling
void initializeSnowV(uint32_t *LFSR, uint32_t *FSM, const uint8_t *key, const uint8_t *nonce) {
    for (int i = 0; i < 8; i++) {
        LFSR[i] = ((uint32_t *)key)[i];
    }
    
    for (int i = 8; i < 12; i++) {
        LFSR[i] = ((uint32_t *)nonce)[i - 8];
    }
    
    FSM[0] = FSM[1] = FSM[2] = 0;
}

// Update LFSR dan FSM sesuai aturan SNOW-V
void updateSnowV(uint32_t *LFSR, uint32_t *FSM) {
    uint32_t s = (rotate_left(LFSR[0], 8) + FSM[0]) ^ FSM[2];
    uint32_t t = rotate_left(LFSR[7], 16) + LFSR[0];

    FSM[2] = FSM[1];
    FSM[1] = FSM[0];
    FSM[0] = (LFSR[7] + FSM[0]) ^ s;

    // Update LFSR berdasarkan keystream
    for (int i = 11; i > 0; i--) {
        LFSR[i] = LFSR[i - 1];
    }
    LFSR[0] = gf_mult(t, 0x1B) ^ rotate_left(LFSR[11], 8);
}

// Fungsi untuk menghasilkan keystream
void generateSnowVKeystream(uint32_t *LFSR, uint32_t *FSM, uint8_t *keystream, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        updateSnowV(LFSR, FSM);
        uint32_t keystream32 = FSM[0] ^ LFSR[11];
        ((uint32_t *)keystream)[i / 4] = keystream32;
    }
}

// Fungsi enkripsi dan dekripsi
void snowVEncryptDecrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32], const uint8_t nonce[16]) {
    uint32_t LFSR[12], FSM[3];
    
    // Inisialisasi LFSR dan FSM
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

void encryptMessage() {
    const char *plaintext = "Hello ESP-8266!!!";
    size_t len = strlen(plaintext);
    
    uint8_t ciphertext[len];

    Serial.print("Original Data: ");
    Serial.println(plaintext);
    Serial.print("Plaintext Size: ");
    Serial.println(len);

    // Mulai waktu komputasi enkripsi
    auto start = high_resolution_clock::now();

    // Enkripsi
    snowVEncryptDecrypt((const uint8_t *)plaintext, ciphertext, len, key, nonce);

    // Selesai waktu komputasi enkripsi
    auto end = high_resolution_clock::now();

    auto encryptDuration = duration_cast<microseconds>(end - start).count();

    Serial.print("Encrypted Data: ");
    for (int i = 0; i < len; i++) {
        Serial.print(ciphertext[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    Serial.print("Encryption Time Computation: ");
    Serial.print(encryptDuration);
    Serial.println(" mikrosecond (μs)");
    Serial.println("------------------------------------------------------");
}

void setup() {
    Serial.begin(115200);
    // Cek apakah ESP8266 baru bangun dari light sleep
    if (ESP.getResetReason() == "Light-Sleep Wake") {
        Serial.println("Waking up from light sleep...");
    } else {
        Serial.println("Normal boot...");
    }

    WiFi.mode(WIFI_STA);

}

void loop() {
    // unsigned long currentMillis = millis();

    // if (!isPaired && (currentMillis - lastPairingAttempt >= pairingInterval)) {
    //     Serial.println("Attempting to pair...");
    //     isPaired = pairWithPeer();
    //     lastPairingAttempt = currentMillis;
    // }

    // if (isPaired) {
        encryptMessage();
        //delay(1);        
        // Masuk ke light sleep setelah mengirim
        //Serial.println("Entering light sleep for 3 seconds...");
        // Light sleep dengan interval waktu
        // Panggil WiFi.sleep() untuk menonaktifkan WiFi dan memasuki mode sleep
        //WiFi.forceSleepBegin();
        delay(1000);  // Light sleep selama 5 detik
        //WiFi.forceSleepWake(); // Wake up from light sleep
    // }
}
