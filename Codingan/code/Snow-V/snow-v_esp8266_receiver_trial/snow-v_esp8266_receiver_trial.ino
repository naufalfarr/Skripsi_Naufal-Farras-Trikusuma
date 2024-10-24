#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
using namespace std::chrono;

// Kunci 256-bit (32 byte)
const uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// Nonce 128-bit (16 byte)
const uint8_t nonce[16] = {
    0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint32_t counter = 1; // Counter untuk enkripsi

// Buffer untuk menyimpan data terfragmentasi
uint8_t receivedData[10240]; // Maks 10KB data
size_t totalDataLen = 0;     // Panjang total data diterima
bool allFragmentsReceived = false; // Status apakah semua fragmen diterima

// Fungsi inisialisasi SNOW-V
void initializeSnowV(uint32_t *LFSR, uint32_t *FSM) {
    memcpy(LFSR, key, 32);
    memcpy(LFSR + 8, nonce, 16);
    memset(FSM, 0, 3 * sizeof(uint32_t));
}

// Fungsi untuk menghasilkan keystream
void generateSnowVKeystream(uint32_t *LFSR, uint32_t *FSM, uint8_t *keystream, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t f = (FSM[0] + LFSR[0]) ^ FSM[2];
        FSM[2] = FSM[1];
        FSM[1] = FSM[0];
        FSM[0] = f;

        uint32_t s = LFSR[11];
        for (int j = 11; j > 0; j--) {
            LFSR[j] = LFSR[j - 1];
        }
        LFSR[0] = s ^ f;

        ((uint32_t *)keystream)[i / 4] = f;
    }
}

// Fungsi enkripsi/dekripsi SNOW-V
void snowVEncryptDecrypt(const uint8_t *input, uint8_t *output, size_t len) {
    uint32_t LFSR[12], FSM[3];
    initializeSnowV(LFSR, FSM);

    uint8_t keystream[64];
    size_t i = 0;

    while (i < len) {
        generateSnowVKeystream(LFSR, FSM, keystream, 64);
        for (size_t j = 0; j < 64 && i < len; ++j, ++i) {
            output[i] = input[i] ^ keystream[j];
        }
    }
}

// Callback untuk menerima data
void onDataRecv(uint8_t *mac_addr, uint8_t *incomingData, uint8_t len) {
    uint8_t fragmentNum = incomingData[0]; // Nomor fragmen
    bool isLast = incomingData[1];         // Apakah ini fragmen terakhir

    // Salin data ke buffer
    memcpy(receivedData + (fragmentNum * 240), incomingData + 2, len - 2);
    totalDataLen += (len - 2);

    if (isLast) {
        allFragmentsReceived = true;
    }

    Serial.printf("Received fragment %d, length: %d\n", fragmentNum, len);
}

// Inisialisasi ESP-NOW
bool initESPNow() {
    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE); // Set sebagai receiver
    esp_now_register_recv_cb(onDataRecv);      // Daftarkan callback penerima
    return true;
}

// Fungsi untuk mendekripsi dan menampilkan pesan
void processReceivedMessage() {
    if (allFragmentsReceived) {
      auto start = high_resolution_clock::now();
        uint8_t decryptedData[totalDataLen + 1]; // +1 untuk null-terminator
        snowVEncryptDecrypt(receivedData, decryptedData, totalDataLen);
        decryptedData[totalDataLen] = '\0'; // Null-terminate string
        auto end = high_resolution_clock::now();

        auto encryptDuration = duration_cast<microseconds>(end - start).count();
        Serial.printf("Encryption Time: %ld microseconds\n", encryptDuration);
        

        Serial.println("Decrypted Message:");
        Serial.println((char *)decryptedData);

        // Reset status untuk menerima pesan berikutnya
        totalDataLen = 0;
        allFragmentsReceived = false;
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA); // Set mode WiFi sebagai Station

    if (!initESPNow()) {
        Serial.println("ESP-NOW initialization failed");
    }
}

void loop() {
    processReceivedMessage();
    delay(500); // Jeda kecil untuk menghindari loop berlebihan
}
