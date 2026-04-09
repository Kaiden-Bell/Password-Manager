#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 10
#define RST_PIN 9

#define ACCESS_DENIED_PIN 4
#define ACCESS_PENDING_PIN 5
#define ACCESS_GRANTED_PIN 6

MFRC522 mfrc522(SS_PIN, RST_PIN);


String authorized_UID = ""; // Change to a specific authorized_UID

void clear_LED() {
    digitalWrite(ACCESS_DENIED_PIN, LOW);
    digitalWrite(ACCESS_PENDING_PIN, LOW);
    digitalWrite(ACCESS_GRANTED_PIN, LOW);
}

void show_pending() {
    clear_LED();
    digitalWrite(ACCESS_PENDING_PIN, HIGH);
}

void show_denied() {
    clear_LED();
    digitalWrite(ACCESS_DENIED_PIN, HIGH);
}

void show_granted() {
    clear_LED();
    digitalWrite(ACCESS_GRANTED_PIN, HIGH);
}

String getUID() {
    String content = "";

    for (byte i = 0; i < mfrc522.uid.size; i++) {
        if (i > 0) content += " ";

        if (mfrc522.uid.uidByte[i] < 0x10) {
            content += "0";
        }
        content += String(mfrc522.uid.uidByte[i], HEX);
    }
    content.toUpperCase();
    return content;
}

void setup() {
  Serial.begin(115200);
  SPI.begin();
  mfrc522.PCD_Init();

  pinMode(ACCESS_DENIED_PIN, OUTPUT);
  pinMode(ACCESS_PENDING_PIN, OUTPUT);
  pinMode(ACCESS_GRANTED_PIN, OUTPUT);

  clear_LED();

  Serial.println("Scan an RFID card...");

}

void loop() {
    if (!mfrc522.PICC_IsNewCardPresent()) return;

    if (!mfrc522.PICC_ReadCardSerial()) return;

    show_pending();

    String scannedUID = getUID();

    Serial.print("Card UID:");
    Serial.println(scannedUID);

    delay(300);

    if (scannedUID == authorized_UID) {
        Serial.print("Access Granted");
        show_granted();
    } else {
        Serial.println("Access Denied");
        show_denied();
    }

    delay(2000);

    clear_LED();

    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
}
