#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
using namespace std::chrono;


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

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

void quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = ROTL(d, 16);
    c += d; b ^= c; b = ROTL(b, 12);
    a += b; d ^= a; d = ROTL(d, 8);
    c += d; b ^= c; b = ROTL(b, 7);
}

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
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, // Constant
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
        state[12]++;  // Increment counter

        for (size_t j = 0; j < 64 && i < len; ++j, ++i) {
            block[j] = ((uint8_t *)outputBlock)[j];
            output[i] = input[i] ^ block[j];  // XOR dengan keystream
        }
    }
}

void OnDataRecv(uint8_t *mac_addr, uint8_t *data, uint8_t len) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    
    Serial.printf("Received data from: %s\n", macStr);
    
        // Print the received data (before decryption)
    Serial.print("Received Data: ");
    for (int i = 0; i < len; i++) {
        Serial.print(data[i]);
        Serial.print(" ");
    }
    Serial.println();

    
    if (len > 0) {
      delay(1000);
        uint8_t decryptedData[len];
        auto start = high_resolution_clock::now();
        chacha20EncryptDecrypt(data, decryptedData, len, key, nonce, counter);
        auto end = high_resolution_clock::now();
        auto decryptDuration = duration_cast<microseconds>(end - start).count();

        Serial.print("Decrypted Data: ");
        for (int i = 0; i < len; i++) {
            Serial.print((char)decryptedData[i]);
        }
        Serial.println();
        Serial.print("Decryption Time Computation: ");
        Serial.print(decryptDuration);
        Serial.println(" mikrosecond (μs)");
        Serial.println("------------------------------------------------"); 
               
    } else {
        Serial.println("Error: Received data length is 0");
        Serial.println("------------------------------------------------"); 
    }
}

void setup() {
    Serial.begin(115200);
    while (!Serial) {
        ; // Wait for serial port to connect
    }
    
    Serial.println("ESP-NOW Receiver Node");
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        ESP.restart();
    }
    
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_register_recv_cb(OnDataRecv);

    Serial.print("Receiver MAC Address: ");
    Serial.println(WiFi.macAddress());
    
    Serial.println("Ready to receive data...");
}

void loop() {

}