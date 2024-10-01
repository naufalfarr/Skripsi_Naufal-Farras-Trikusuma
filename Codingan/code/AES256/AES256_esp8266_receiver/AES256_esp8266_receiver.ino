#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Crypto.h>
#include <AES.h>
#include <base64.h>
#include <chrono>

using namespace std::chrono;

// Kunci 256-bit (32 byte)
uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// Buffer untuk menyimpan data terenkripsi
uint8_t receivedData[32]; // Sesuaikan dengan ukuran blok terenkripsi
size_t receivedLen = 0;

// Fungsi untuk menghapus padding (PKCS7)
void removePadding(const uint8_t *input, size_t len, uint8_t *output, size_t &output_len) {
    uint8_t padding_len = input[len - 1]; // Nilai padding berada di byte terakhir
    output_len = len - padding_len;
    memcpy(output, input, output_len);
}

// Fungsi dekripsi AES 256 ECB
void aes256Decrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32]) {
    AES aes;
    aes.set_key(key, 32); // Set kunci untuk AES 256

    for (size_t i = 0; i < len; i += 16) {
        aes.decrypt(input + i, output + i);  // Dekripsi setiap blok 16 byte
    }
}

// Callback ketika menerima pesan melalui ESP-NOW (untuk ESP8266)
void onReceive(uint8_t *mac_addr, uint8_t *data, uint8_t len) {
    Serial.println("Received Encrypted Data (Hex)");
    // Print the received data (before decryption)
    Serial.print("Decrypted Data: ");
    for (int i = 0; i < len; i++) {
        Serial.print(data[i], HEX); // Print in hexadecimal format
        Serial.print(" ");
    }
    Serial.println();

    // Simpan data yang diterima
    memcpy(receivedData, data, len);
    receivedLen = len;

    // Buat buffer untuk plaintext yang sudah di-decrypt
    uint8_t decryptedData[32]; // Buffer hasil dekripsi

    // Catat waktu sebelum dekripsi
    auto start = high_resolution_clock::now();

    // Proses dekripsi
    aes256Decrypt(receivedData, decryptedData, receivedLen, key);

    // Catat waktu setelah dekripsi
    auto end = high_resolution_clock::now();

    // Hitung durasi dekripsi dalam mikrodetik
    auto decryptDuration = duration_cast<microseconds>(end - start).count();

    // Buat buffer untuk plaintext tanpa padding
    uint8_t plaintext[32];
    size_t plaintextLen;
    removePadding(decryptedData, receivedLen, plaintext, plaintextLen);

    // Tampilkan pesan yang didekripsi
    Serial.print("Decrypted Message: ");
    for (size_t i = 0; i < plaintextLen; i++) {
        Serial.print((char)plaintext[i]);
    }
    Serial.println();

    // Tampilkan waktu komputasi
    Serial.print("Decryption Time Computation: ");
    Serial.print(decryptDuration);
    Serial.println(" microsecond (μs)");
    Serial.println("------------------------------------------------");
}

bool initESPNow() {
    if (esp_now_init() != 0) {  // ESP_OK tidak didefinisikan di ESP8266, ganti dengan 0
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);  // Set sebagai slave (receiver)
    esp_now_register_recv_cb(onReceive);        // Daftarkan callback untuk menerima data
    return true;
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
    // Loop ini menunggu data yang diterima
    delay(2500); // Tunggu interval sebelum mengecek kembali
}
