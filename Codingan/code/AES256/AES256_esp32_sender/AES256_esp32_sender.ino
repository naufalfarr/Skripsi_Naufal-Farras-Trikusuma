#include <WiFi.h>
#include <esp_now.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
#include "mbedtls/aes.h"

using namespace std::chrono;

// MAC Address ESP8266 receiver 84:f3:eb:05:50:b7
uint8_t receiverMAC[] = {0x84, 0xF3, 0xEB, 0x05, 0x50, 0xB7};

// Kunci 256-bit (32 byte)
uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// Variabel untuk manajemen koneksi
bool isPaired = false;
unsigned long lastPairingAttempt = 0;
const unsigned long pairingInterval = 5000; // Coba pairing setiap 5 detik

// Fungsi untuk melakukan padding data agar sesuai dengan blok 16 byte AES
void addPadding(const uint8_t *input, size_t len, uint8_t *output, size_t &output_len) {
    size_t padding_len = 16 - (len % 16);
    output_len = len + padding_len;
    memcpy(output, input, len);
    for (size_t i = len; i < output_len; i++) {
        output[i] = padding_len; // PKCS7 Padding
    }
}

// Fungsi enkripsi AES 256 ECB
void aes256Encrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32]) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256); // Set kunci AES 256

    for (size_t i = 0; i < len; i += 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input + i, output + i);
    }

    mbedtls_aes_free(&aes);
}

void onSend(const uint8_t *mac_addr, esp_now_send_status_t status) {
    if (status != ESP_NOW_SEND_SUCCESS) {
        isPaired = false; // Reset pairing status jika pengiriman gagal
    }
    Serial.println("------------------------------------------------");
}

bool initESPNow() {
    if (esp_now_init() != ESP_OK) {
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    esp_now_register_send_cb(onSend);
    return true;
}

bool pairWithPeer() {
    esp_now_peer_info_t peerInfo = {};
    memcpy(peerInfo.peer_addr, receiverMAC, 6);
    peerInfo.channel = 0;
    peerInfo.encrypt = false;

    if (esp_now_add_peer(&peerInfo) != ESP_OK) {
        Serial.println("Failed to add peer");
        return false;
    }
    Serial.println("Pairing successful");
    return true;
}
void printHex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        // Print each byte in hex format (2 digits)
        if (data[i] < 0x10) {
            Serial.print("0"); // Add leading zero for single-digit hex values
        }
        Serial.print(data[i], HEX);
        Serial.print(" ");
    }
    Serial.println();
}

void sendEncryptedMessage() {
    const char *plaintext = "Hello ESP-8266!";
    size_t len = strlen(plaintext);
    
    // Buat buffer untuk plaintext dengan padding
    uint8_t paddedPlaintext[32]; // Ukuran blok maksimum yang ditambah padding
    size_t paddedLen;
    
    addPadding((const uint8_t *)plaintext, len, paddedPlaintext, paddedLen);

    uint8_t ciphertext[paddedLen];

    // Serial.print("Original Message: ");
    // Serial.println(plaintext);
    // Serial.println("---");
    //     // Tampilkan pesan asli dalam bentuk hex
    // Serial.print("Original Message (Hex): ");
    // printHex((const uint8_t*)plaintext, len);

    // Catat waktu sebelum enkripsi menggunakan chrono
    auto start = high_resolution_clock::now();

    // Proses enkripsi
    aes256Encrypt(paddedPlaintext, ciphertext, paddedLen, key);

    // Catat waktu setelah enkripsi menggunakan chrono
    auto end = high_resolution_clock::now();

    // Hitung durasi enkripsi
    auto encryptDuration = duration_cast<microseconds>(end - start).count();

    // Print the encrypted ciphertext
    Serial.print("Encrypted Message: ");
    for (int i = 0; i < paddedLen; i++) {
        Serial.print(ciphertext[i]);
        Serial.print(" ");
    }
    Serial.println();

    // Tampilkan waktu komputasi
    Serial.print("Waktu komputasi enkripsi: ");
    Serial.print(encryptDuration);
    Serial.println(" mikrodetik");    

    // Kirim data terenkripsi
    esp_err_t result = esp_now_send(receiverMAC, ciphertext, paddedLen);
    if (result == ESP_OK) {
        Serial.println("Sent with success");
    } else {
        Serial.println("Error sending the data");
        isPaired = false;
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (!initESPNow()) {
        Serial.println("ESP-NOW initialization failed");
        ESP.restart();
    }
}

void loop() {
    unsigned long currentMillis = millis();

    if (!isPaired && (currentMillis - lastPairingAttempt >= pairingInterval)) {
        Serial.println("Attempting to pair...");
        isPaired = pairWithPeer();
        lastPairingAttempt = currentMillis;
    }

    if (isPaired) {
        sendEncryptedMessage();
        delay(7500); 
    }
}
