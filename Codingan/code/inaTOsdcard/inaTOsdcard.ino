#include <WiFi.h>
#include <Wire.h>
#include <Adafruit_INA219.h>
#include <time.h>
#include <sys/time.h>
#include <SD.h>
#include <SPI.h>

#define SD_CS 5  // Pin CS untuk kartu SD
#define BUFFER_SIZE 50  // Ukuran buffer

// Data Wi-Fi
const char* ssid = "farras";
const char* password = "123456789"; 

// Deklarasi zona waktu (UTC +7 untuk Indonesia Barat)
const long gmtOffset_sec = 7 * 3600;
const int daylightOffset_sec = 0;

// Nama file untuk data CSV
const char* filename = "/sensor_data.csv";

// Buffer untuk menyimpan data
String dataBuffer[BUFFER_SIZE];
int bufferIndex = 0;

// Inisialisasi sensor INA219
Adafruit_INA219 ina219;

// Fungsi untuk menginisialisasi waktu NTP
void setupTime() {
  configTime(gmtOffset_sec, daylightOffset_sec, "pool.ntp.org", "time.nist.gov");
}

// Fungsi untuk mendapatkan timestamp dengan milidetik
String getTimeWithMillis() {
  struct timeval tv;
  struct tm timeinfo;
  
  if (!getLocalTime(&timeinfo)) {
    Serial.println("Gagal mendapatkan waktu");
    return "00:00:00.000";
  }
  
  gettimeofday(&tv, NULL);
  
  char timeStringBuff[50];
  strftime(timeStringBuff, sizeof(timeStringBuff), "%H:%M:%S", &timeinfo);
  
  char millisStringBuff[60];
  sprintf(millisStringBuff, "%s.%03d", timeStringBuff, (int)(tv.tv_usec / 1000));
  
  return String(millisStringBuff);
}

// Fungsi untuk menulis data dari buffer ke SD card
void writeBufferToSD() {
  File dataFile = SD.open(filename, FILE_APPEND);
  if (dataFile) {
    for (int i = 0; i < bufferIndex; i++) {
      dataFile.println(dataBuffer[i]);
    }
    dataFile.flush();
    dataFile.close();
    Serial.println("Data dari buffer ditulis ke SD card.");
    bufferIndex = 0;  // Reset buffer index
  } else {
    Serial.println("Error menulis ke file CSV!");
  }
}

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    delay(1);
  }

  // Hubungkan ke Wi-Fi
  Serial.print("Menghubungkan ke Wi-Fi...");
  WiFi.begin(ssid, password);
  int retryCount = 0;
  while (WiFi.status() != WL_CONNECTED && retryCount < 50) {
    delay(1000);
    Serial.print(".");
    retryCount++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(" Terhubung!");
    setupTime();
  } else {
    Serial.println(" Gagal terhubung ke WiFi.");
  }

  // Inisialisasi SD card
  if (!SD.begin(SD_CS)) {
    Serial.println("Error menginisialisasi SD card!");
    return;
  }

  // Inisialisasi sensor INA219
  if (!ina219.begin()) {
    Serial.println("Gagal menemukan chip INA219!");
    while (1) { delay(10); }
  }

  // Buat atau buka file CSV dan tulis header
  File dataFile = SD.open(filename, FILE_WRITE);
  if (dataFile) {
    dataFile.println("Timestamp,Power (mW),Bus Voltage (V),Load Voltage (V),Current (mA)");
    dataFile.close();
    Serial.println("File CSV dibuat dengan header.");
  } else {
    Serial.println("Error membuat file CSV!");
  }
}

void loop() {
  // Baca nilai dari sensor INA219
  float shuntvoltage = ina219.getShuntVoltage_mV();
  float busvoltage = ina219.getBusVoltage_V();
  float current_mA = ina219.getCurrent_mA();
  float power_mW = ina219.getPower_mW();
  float loadvoltage = busvoltage + (shuntvoltage / 1000);

  // Dapatkan timestamp
  String timestamp = getTimeWithMillis();

  // Buat string data dalam format CSV
  String dataEntry = timestamp + "," + 
                    String(power_mW) + "," + 
                    String(busvoltage) + "," + 
                    String(loadvoltage) + "," + 
                    String(current_mA);

  // Simpan ke buffer
  dataBuffer[bufferIndex] = dataEntry;
  bufferIndex++;

  // Jika buffer penuh, tulis ke SD card
  if (bufferIndex >= BUFFER_SIZE) {
    writeBufferToSD();
  }

  // Delay untuk jeda pembacaan data
  delay(10);  // Simpan data setiap 10ms
}