#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Crypto.h>
#include <AES.h>
#include <base64.h>
#include <chrono>

using namespace std::chrono;

// MAC Address ESP8266 receiver (ganti dengan MAC address yang sesuai)
uint8_t receiverMAC[] = {0x84, 0xF3, 0xEB, 0x05, 0x50, 0xB7};

// Kunci 256-bit (32 byte)
uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

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
    AES aes;
    aes.set_key(key, 32); // Set kunci untuk AES 256

    for (size_t i = 0; i < len; i += 16) {
        aes.encrypt(input + i, output + i);  // Enkripsi setiap blok 16 byte
    }
}

// Callback ketika data dikirim
void onSend(uint8_t *mac_addr, uint8_t sendStatus) {
    Serial.print("Send Status: ");
    if (sendStatus == 0) {
        Serial.println("Success");
    } else {
        Serial.println("Failed");
    }
    Serial.println("------------------------------------------------");
}

bool initESPNow() {
    if (esp_now_init() != 0) {  // ESP_OK tidak didefinisikan di ESP8266, ganti dengan 0
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);  // Set sebagai controller (sender)
    esp_now_register_send_cb(onSend);                // Daftarkan callback untuk pengiriman data
    return true;
}

bool pairWithReceiver() {
    // Pairing dengan peer (receiver)
    if (esp_now_is_peer_exist(receiverMAC)) {
        return true; // Peer sudah terdaftar
    }

    if (esp_now_add_peer(receiverMAC, ESP_NOW_ROLE_SLAVE, 1, NULL, 0) != 0) {  // ESP8266 menggunakan role
        Serial.println("Failed to add peer");
        return false;
    }
    return true;
}

void sendEncryptedMessage() {
    const char *plaintext = "30.40,71.7030.40,71.7030";
    size_t len = strlen(plaintext);

    // Buat buffer untuk plaintext dengan padding
    uint8_t paddedPlaintext[32]; // Ukuran blok maksimum yang ditambah padding
    size_t paddedLen;

    addPadding((const uint8_t *)plaintext, len, paddedPlaintext, paddedLen);

    uint8_t ciphertext[32]; // Buffer untuk menyimpan ciphertext

    // Catat waktu sebelum enkripsi menggunakan chrono
    auto start = high_resolution_clock::now();

    // Proses enkripsi
    aes256Encrypt(paddedPlaintext, ciphertext, paddedLen, key);

    // Catat waktu setelah enkripsi menggunakan chrono
    auto end = high_resolution_clock::now();

    // Hitung durasi enkripsi
    auto encryptDuration = duration_cast<microseconds>(end - start).count();

    // Tampilkan pesan asli dan ciphertext
    Serial.print("Original Data: ");
    Serial.println(plaintext);

    Serial.print("Encrypted Data (Hex): ");
    for (int i = 0; i < paddedLen; i++) {
        if (ciphertext[i] < 0x10) Serial.print("0"); // Tambahkan nol jika perlu
        Serial.print(ciphertext[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    // Tampilkan waktu komputasi
    Serial.print("Encryption Time Computation: ");
    Serial.print(encryptDuration);
    Serial.println(" microsecond (μs)");

    //Kirim data terenkripsi
    uint8_t sendStatus = esp_now_send(receiverMAC, ciphertext, paddedLen);
    if (sendStatus == 0) {
        Serial.println("Sent with success");
    } else {
        Serial.println("Error sending the data");
    }
}

void encrypt() {
    const char *plaintext = "rithms";
    size_t len = strlen(plaintext);

    // Buat buffer untuk plaintext dengan padding
    uint8_t paddedPlaintext[32]; // Ukuran blok maksimum yang ditambah padding
    size_t paddedLen;

    addPadding((const uint8_t *)plaintext, len, paddedPlaintext, paddedLen);

    uint8_t ciphertext[32]; // Buffer untuk menyimpan ciphertext

    // Catat waktu sebelum enkripsi menggunakan chrono
    auto start = high_resolution_clock::now();

    // Proses enkripsi
    aes256Encrypt(paddedPlaintext, ciphertext, paddedLen, key);
    // Catat waktu setelah enkripsi menggunakan chrono
    auto end = high_resolution_clock::now();

    // Hitung durasi enkripsi
    auto encryptDuration = duration_cast<microseconds>(end - start).count();

    // Tampilkan pesan asli dan ciphertext
    Serial.print("Original Data: ");
    Serial.println(plaintext);

    Serial.print("Encrypted Data (Hex): ");
    for (int i = 0; i < paddedLen; i++) {
        if (ciphertext[i] < 0x10) Serial.print("0"); // Tambahkan nol jika perlu
        Serial.print(ciphertext[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    // Tampilkan waktu komputasi
    Serial.print("Encryption Time Computation: ");
    Serial.print(encryptDuration);
    Serial.println(" microsecond (μs)");
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (!initESPNow()) {
        Serial.println("ESP-NOW initialization failed");
        ESP.restart();
    }

    if (!pairWithReceiver()) {
        Serial.println("Pairing with receiver failed");
        ESP.restart();
    }
}

void loop() {
    // // Kirim pesan setiap 5 detik
    // sendEncryptedMessage();
    // delay(5000);
        encrypt();
        delay(1);     
        // Masuk ke light sleep setelah mengirim
        Serial.println("Entering light sleep for 3 seconds...");
        // Light sleep dengan interval waktu
        // Panggil WiFi.sleep() untuk menonaktifkan WiFi dan memasuki mode sleep
        WiFi.forceSleepBegin();
        delay(3000);  // Light sleep selama 5 detik
        WiFi.forceSleepWake(); // Wake up from light sleep    
}
