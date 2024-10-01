#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
using namespace std::chrono;

// MAC Address ESP8266 receiver (sesuaikan dengan MAC address receiver Anda)
uint8_t receiverMAC[] = {0x84, 0xF3, 0xEB, 0x05, 0x50, 0xB7};

// Kunci 256-bit (32 byte)
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

// Counter
uint32_t counter = 1;

// Variabel untuk manajemen koneksi
bool isPaired = false;
unsigned long lastPairingAttempt = 0;
const unsigned long pairingInterval = 5000; // Coba pairing setiap 5 detik

// Fungsi untuk inisialisasi state SNOW-V
void initializeSnowV(uint32_t *LFSR, uint32_t *FSM, const uint8_t *key, const uint8_t *nonce) {
    // Inisialisasi LFSR dengan key dan nonce (khusus untuk SNOW-V)
    // Implementasi ini perlu diperhatikan dari referensi SNOW-V spesifikasi
    // LFSR[0-7] diinisialisasi dengan key
    for (int i = 0; i < 8; i++) {
        LFSR[i] = ((uint32_t *)key)[i];
    }
    
    // LFSR[8-11] diinisialisasi dengan nonce
    for (int i = 8; i < 12; i++) {
        LFSR[i] = ((uint32_t *)nonce)[i - 8];
    }

    // FSM diinisialisasi ke 0
    FSM[0] = FSM[1] = FSM[2] = 0;
}

// Fungsi untuk menghasilkan keystream
void generateSnowVKeystream(uint32_t *LFSR, uint32_t *FSM, uint8_t *keystream, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        // Update FSM dan LFSR berdasarkan aturan SNOW-V
        // Simulasi untuk 32-bit keystream
        uint32_t f = (FSM[0] + LFSR[0]) ^ FSM[2];
        
        FSM[2] = FSM[1];
        FSM[1] = FSM[0];
        FSM[0] = f;

        uint32_t s = LFSR[11];
        for (int j = 11; j > 0; j--) {
            LFSR[j] = LFSR[j-1];
        }
        LFSR[0] = s ^ f;

        // Hasil keystream ditulis ke buffer
        ((uint32_t *)keystream)[i / 4] = f;
    }
}

// Fungsi enkripsi XOR menggunakan SNOW-V
void snowVEncryptDecrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32], const uint8_t nonce[16], uint32_t counter) {
    uint32_t LFSR[12], FSM[3];
    
    // Inisialisasi LFSR dan FSM
    initializeSnowV(LFSR, FSM, key, nonce);
    
    // Buffer untuk menyimpan keystream
    uint8_t keystream[64];
    size_t i = 0;

    while (i < len) {
        // Generate keystream untuk blok 64 byte
        generateSnowVKeystream(LFSR, FSM, keystream, 64);

        // XOR keystream dengan plaintext untuk enkripsi
        for (size_t j = 0; j < 64 && i < len; ++j, ++i) {
            output[i] = input[i] ^ keystream[j];
        }
    }
}

void onSend(uint8_t *mac_addr, uint8_t sendStatus) {
    if (sendStatus != 0) {
        isPaired = false; // Reset pairing status jika pengiriman gagal
    }
    Serial.println("------------------------------------------------");
}

bool initESPNow() {
    if (esp_now_init() != 0) { // ESP8266 menggunakan 0 sebagai indikator sukses
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);  // Set peran sender
    esp_now_register_send_cb(onSend);
    return true;
}

bool pairWithPeer() {
    if (esp_now_is_peer_exist(receiverMAC)) {
        return true; // Peer sudah ada
    }

    if (esp_now_add_peer(receiverMAC, ESP_NOW_ROLE_SLAVE, 1, NULL, 0) != 0) {
        Serial.println("Failed to add peer");
        return false;
    }
    Serial.println("Pairing successful");
    return true;
}

void sendEncryptedMessage() {
    const char *plaintext = "Hello ESP-8266!";
    size_t len = strlen(plaintext);
    
    uint8_t ciphertext[len];

    Serial.print("Original Data: ");
    Serial.println(plaintext);

    // Catat waktu sebelum enkripsi menggunakan chrono
    auto start = high_resolution_clock::now();

    // Proses enkripsi
    snowVEncryptDecrypt((const uint8_t *)plaintext, ciphertext, len, key, nonce, counter);

    // Catat waktu setelah enkripsi menggunakan chrono
    auto end = high_resolution_clock::now();

    // Hitung durasi enkripsi
    auto encryptDuration = duration_cast<microseconds>(end - start).count();

    // Print the encrypted ciphertext
    Serial.print("Encrypted Data: ");
    for (int i = 0; i < len; i++) {
        Serial.print(ciphertext[i]);
        Serial.print(" ");
    }
    Serial.println();

    // Tampilkan waktu komputasi
    Serial.print("Encryption Time Computation: ");
    Serial.print(encryptDuration);
    Serial.println(" mikrosecond (μs)");    

    // Kirim data terenkripsi
    uint8_t sendStatus = esp_now_send(receiverMAC, ciphertext, len);
    if (sendStatus == 0) {
        Serial.println("Sent with success");
    } else {
        Serial.println("Error sending the data");
        isPaired = false;
    }
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
        delay(1);        
        // Masuk ke light sleep setelah mengirim
        Serial.println("Entering light sleep for 5 seconds...");
        // Light sleep dengan interval waktu
        // Panggil WiFi.sleep() untuk menonaktifkan WiFi dan memasuki mode sleep
        WiFi.forceSleepBegin();
        delay(5000);  // Light sleep selama 5 detik
        WiFi.forceSleepWake(); // Wake up from light sleep
    }
}
