#include <ESP8266WiFi.h>
#include <espnow.h>
#include <string.h>
#include <chrono>
using namespace std::chrono;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

// AES S-box
const u8 SBox[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

const u8 Sigma[16] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};

class SNOW_V_ESP {
private:
    u16 A[16], B[16];
    u32 R1[4], R2[4], R3[4];
    u32 AesKey1[4];
    u32 AesKey2[4];

    #define MAKEU32(a, b) (((u32)(a) << 16) | ((u32)(b)))
    #define MAKEU16(a, b) (((u16)(a) << 8) | ((u16)(b)))
    #define ROTL32(word32, offset) ((word32 << offset) | (word32 >> (32 - offset)))

    void aes_enc_round(u32* result, u32* state, u32* roundKey) {
        #define SB(index, offset) (((u32)(SBox[(index) % 16])) << (offset * 8)) // Pastikan SBox didefinisikan

        u32 w, t;
        u8 sb[16];

        for(int i = 0; i < 4; i++)
            for(int j = 0; j < 4; j++)
                sb[i * 4 + j] = SBox[(state[i] >> (j * 8)) & 0xff];

        for(int j = 0; j < 4; j++) {
            w = SB(j*4 + 0, 3) | SB(j*4 + 5, 0) | SB(j*4 + 10, 1) | SB(j*4 + 15, 2);
            t = ROTL32(w, 16) ^ ((w << 1) & 0xfefefefeUL) ^ (((w >> 7) & 0x01010101UL) * 0x1b);
            result[j] = roundKey[j] ^ w ^ t ^ ROTL32(t, 8);
        }
    }

    u16 mul_x(u16 v, u16 c) {
        return (v & 0x8000) ? ((v << 1) ^ c) : (v << 1);
    }

    u16 mul_x_inv(u16 v, u16 d) {
        return (v & 0x0001) ? ((v >> 1) ^ d) : (v >> 1);
    }

    void permute_sigma(u32* state) {
        u8 tmp[16];
        for(int i = 0; i < 16; i++)
            tmp[i] = (u8)(state[Sigma[i] >> 2] >> ((Sigma[i] & 3) << 3));

        for(int i = 0; i < 4; i++)
            state[i] = MAKEU32(MAKEU16(tmp[4*i + 3], tmp[4*i + 2]),
                                MAKEU16(tmp[4*i + 1], tmp[4*i]));
    }

    void fsm_update() {
        u32 R1temp[4];
        memcpy(R1temp, R1, sizeof(R1));

        for(int i = 0; i < 4; i++) {
            u32 T2 = MAKEU32(A[2*i + 1], A[2*i]);
            R1[i] = (T2 ^ R3[i]) + R2[i];
        }

        permute_sigma(R1);
        aes_enc_round(R3, R2, AesKey2);
        aes_enc_round(R2, R1temp, AesKey1);
    }

    void lfsr_update() {
        for(int i = 0; i < 8; i++) {
            u16 u = mul_x(A[0], 0x990f) ^ A[1] ^ mul_x_inv(A[8], 0xcc87) ^ B[0];
            u16 v = mul_x(B[0], 0xc963) ^ B[3] ^ mul_x_inv(B[8], 0xe4b1) ^ A[0];

            for(int j = 0; j < 15; j++) {
                A[j] = A[j + 1];
                B[j] = B[j + 1];
            }
            A[15] = u;
            B[15] = v;
        }
    }

public:
    void keystream(u8* z) {
        for(int i = 0; i < 4; i++) {
            u32 T1 = MAKEU32(B[2*i + 9], B[2*i + 8]);
            u32 v = (T1 + R1[i]) ^ R2[i];

            z[i * 4 + 0] = (v >> 0) & 0xff;
            z[i * 4 + 1] = (v >> 8) & 0xff;
            z[i * 4 + 2] = (v >> 16) & 0xff;
            z[i * 4 + 3] = (v >> 24) & 0xff;
        }
        fsm_update();
        lfsr_update();
    }

    void keyiv_setup(const u8* key, const u8* iv, bool is_aead_mode = false) {
        for(int i = 0; i < 8; i++) {
            A[i] = MAKEU16(iv[2*i + 1], iv[2*i]);
            A[i + 8] = MAKEU16(key[2*i + 1], key[2*i]);
            B[i] = 0x0000;
            B[i + 8] = MAKEU16(key[2*i + 17], key[2*i + 16]);
        }

        if(is_aead_mode) {
            B[0] = 0x6C41; B[1] = 0x7865; B[2] = 0x6B45; B[3] = 0x2064;
            B[4] = 0x694A; B[5] = 0x676E; B[6] = 0x6854; B[7] = 0x6D6F;
        }

        memset(R1, 0, sizeof(R1));
        memset(R2, 0, sizeof(R2));
        memset(R3, 0, sizeof(R3));

        for(int i = 0; i < 16; i++) {
            u8 z[16];
            keystream(z);

            for(int j = 0; j < 8; j++)
                A[j + 8] ^= MAKEU16(z[2*j + 1], z[2*j]);

            if(i == 14)
                for(int j = 0; j < 4; j++)
                    R1[j] ^= MAKEU32(MAKEU16(key[4*j + 3], key[4*j + 2]),
                                     MAKEU16(key[4*j + 1], key[4*j]));

            if(i == 15)
                    for(int j = 0; j < 4; j++)
                        R1[j] ^= MAKEU32(MAKEU16(key[4*j + 19], key[4*j + 18]),
                                         MAKEU16(key[4*j + 17], key[4*j + 16]));
        }
    }

    // Enkripsi data
    void encrypt(const u8* input, u8* output, size_t length) {
        u8 keystream_block[16];

          for (size_t i = 0; i < length; i += 16) {
            size_t block_size = std::min<size_t>(16, length - i); // Gunakan std::min dengan casting ke <size_t>

            for(size_t j = 0; j < block_size; j++) {
                output[i + j] = input[i + j] ^ keystream_block[j];
            }
        }
    }
};

// Buffer untuk menyimpan fragmen yang diterima
struct MessageBuffer {
    uint8_t* data;
    size_t length;
    bool* receivedFragments;
    uint8_t totalFragments;
    bool complete;
    
    MessageBuffer() : data(nullptr), length(0), receivedFragments(nullptr), 
                     totalFragments(0), complete(false) {}
                     
    void init(size_t maxSize) {
        if(data) delete[] data;
        if(receivedFragments) delete[] receivedFragments;
        
        data = new uint8_t[maxSize];
        receivedFragments = new bool[256](); // Max 256 fragments
        length = 0;
        totalFragments = 0;
        complete = false;
    }
    
    ~MessageBuffer() {
        if(data) delete[] data;
        if(receivedFragments) delete[] receivedFragments;
    }
};

MessageBuffer msgBuffer;
SNOW_V_ESP snow_v;

// 256-bit key (harus sama dengan sender)
const u8 key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// 128-bit IV (harus sama dengan sender)
const u8 iv[16] = {
    0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void processFragment(const uint8_t* fragment, size_t length) {
    if(length < 3) return; // Minimal harus ada header (fragmentNum + isLast) + 1 byte data
    
    uint8_t fragmentNum = fragment[0];
    bool isLast = fragment[1];
    const uint8_t* data = fragment + 2;
    size_t dataLength = length - 2;
    
    // Jika ini fragment pertama, inisialisasi buffer
    if(fragmentNum == 0) {
        msgBuffer.init(16384); // Max 16KB message size
    }
    
    // Simpan data
    if(!msgBuffer.receivedFragments[fragmentNum]) {
        memcpy(msgBuffer.data + msgBuffer.length, data, dataLength);
        msgBuffer.length += dataLength;
        msgBuffer.receivedFragments[fragmentNum] = true;
        
        if(fragmentNum + 1 > msgBuffer.totalFragments) {
            msgBuffer.totalFragments = fragmentNum + 1;
        }
    }
    
    // Cek apakah semua fragment sudah diterima
    if(isLast) {
        bool allReceived = true;
        for(uint8_t i = 0; i < msgBuffer.totalFragments; i++) {
            if(!msgBuffer.receivedFragments[i]) {
                allReceived = false;
                break;
            }
        }
        
        if(allReceived) {
            msgBuffer.complete = true;
        }
    }
}

void decryptAndPrint() {
    if(!msgBuffer.complete || msgBuffer.length == 0) return;
    
    uint8_t* plaintext = new uint8_t[msgBuffer.length + 1];
    
    // Measure decryption time
    auto start = high_resolution_clock::now();
    
    // Setup key and IV
    snow_v.keyiv_setup(key, iv);
    
    // Decrypt
    snow_v.encrypt(msgBuffer.data, plaintext, msgBuffer.length); // SNOW-V enkripsi = dekripsi
    plaintext[msgBuffer.length] = 0; // Null terminator
    
    auto end = high_resolution_clock::now();
    auto decryptDuration = duration_cast<microseconds>(end - start).count();
    
    // Print results
    Serial.printf("Decryption Time: %ld microseconds\n", decryptDuration);
    Serial.printf("Message Length: %d bytes\n", msgBuffer.length);
    
    Serial.print("Received Ciphertext (hex): ");
    for(size_t i = 0; i < msgBuffer.length; i++) {
        Serial.printf("%02X", msgBuffer.data[i]);
    }
    Serial.println();
    
    Serial.print("Decrypted Text: ");
    Serial.println((char*)plaintext);
    Serial.println("------------------------------------------------");
    
    delete[] plaintext;
    msgBuffer.complete = false; // Reset for next message
}

void onReceive(uint8_t *mac, uint8_t *data, uint8_t len) {
    processFragment(data, len);
    if(msgBuffer.complete) {
        decryptAndPrint();
    }
}

bool initESPNow() {
    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_register_recv_cb(onReceive);
    return true;
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    if (!initESPNow()) {
        Serial.println("ESP-NOW initialization failed");
        ESP.restart();
    }
    
    msgBuffer.init(16384); // Initialize message buffer
    Serial.println("Decryption Node Ready!");
}

void loop() {
    // Main processing dilakukan di callback onReceive
    delay(1);
}