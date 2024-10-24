#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
using namespace std::chrono;

#define MAX_INPUT_SIZE 16384
#define MAX_CHUNK_SIZE 250
#define TIMEOUT_MS 100 // Timeout 100ms untuk mendeteksi akhir transmisi

// Kunci 256-bit (32 byte)
uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// Nonce 96-bit (12 byte)
uint8_t nonce[12] = {
    0x00, 0x00, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x4A,
    0x00, 0x00, 0x00, 0x00
};

// Counter
uint32_t counter = 1;

// Buffer dan variabel status
uint8_t receivedData[MAX_INPUT_SIZE];
size_t totalReceived = 0;
unsigned long lastReceiveTime = 0;
bool isReceiving = false;

// Rotasi ke kiri
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

// Fungsi ChaCha quarter round
void quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = ROTL(d, 16);
    c += d; b ^= c; b = ROTL(b, 12);
    a += b; d ^= a; d = ROTL(d, 8);
    c += d; b ^= c; b = ROTL(b, 7);
}

// Fungsi untuk menghasilkan satu blok 64-byte
void chacha20Block(uint32_t out[16], const uint32_t in[16]) {
    memcpy(out, in, sizeof(uint32_t) * 16);
    for (int i = 0; i < 10; i++) {
        quarterRound(out[0], out[4], out[ 8], out[12]);
        quarterRound(out[1], out[5], out[ 9], out[13]);
        quarterRound(out[2], out[6], out[10], out[14]);
        quarterRound(out[3], out[7], out[11], out[15]);

        quarterRound(out[0], out[5], out[10], out[15]);
        quarterRound(out[1], out[6], out[11], out[12]);
        quarterRound(out[2], out[7], out[ 8], out[13]);
        quarterRound(out[3], out[4], out[ 9], out[14]);
    }
    for (int i = 0; i < 16; i++) {
        out[i] += in[i];
    }
}

void chacha20EncryptDecrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16] = {
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
        ((uint32_t *)key)[0], ((uint32_t *)key)[1], ((uint32_t *)key)[2], ((uint32_t *)key)[3],
        ((uint32_t *)key)[4], ((uint32_t *)key)[5], ((uint32_t *)key)[6], ((uint32_t *)key)[7],
        counter,
        ((uint32_t *)nonce)[0], ((uint32_t *)nonce)[1], ((uint32_t *)nonce)[2]
    };

    uint8_t block[64];
    size_t i = 0;

    while (i < len) {
        uint32_t outputBlock[16];
        chacha20Block(outputBlock, state);
        state[12]++;

        for (size_t j = 0; j < 64 && i < len; ++j, ++i) {
            block[j] = ((uint8_t *)outputBlock)[j];
            output[i] = input[i] ^ block[j];
        }
    }
}

void processReceivedData() {
    if (totalReceived > 0) {
        
        
        // Alokasikan memori untuk plaintext
        uint8_t *plaintext = (uint8_t *)malloc(totalReceived + 1);
        if (plaintext == nullptr) {
            Serial.println("Memory allocation failed!");
            return;
        }

        Serial.print("Total Received Data Size: ");
        Serial.print(totalReceived);
        Serial.println(" Byte (B)");
        delay(1000);        

        auto start = high_resolution_clock::now();
        // Proses dekripsi
        chacha20EncryptDecrypt(receivedData, plaintext, totalReceived, key, nonce, counter);
        plaintext[totalReceived] = '\0';

        auto end = high_resolution_clock::now();
        auto decryptDuration = duration_cast<microseconds>(end - start).count();

        Serial.print("Decrypted Data: ");
        Serial.println((char*)plaintext);
        Serial.print("Decryption Time: ");
        Serial.print(decryptDuration);
        Serial.println(" microseconds");
        Serial.println("------------------------------------------------");

        // Reset untuk penerimaan berikutnya
        totalReceived = 0;
        isReceiving = false;
        
        free(plaintext);
    }
}

void onDataReceived(uint8_t *mac_addr, uint8_t *data, uint8_t len) {
    if (totalReceived + len <= MAX_INPUT_SIZE) {
        memcpy(receivedData + totalReceived, data, len);
        totalReceived += len;
        lastReceiveTime = millis();
        isReceiving = true;
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    Serial.print("MAC Address: ");
    Serial.println(WiFi.macAddress());

    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        ESP.restart();
    }
    
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_register_recv_cb(onDataReceived);
    Serial.println("Receiver Ready");
}

void loop() {
    // Cek timeout jika sedang menerima data
    if (isReceiving && (millis() - lastReceiveTime > TIMEOUT_MS)) {
        processReceivedData();
    }
    yield(); // Beri kesempatan untuk ESP8266 menangani background tasks
}