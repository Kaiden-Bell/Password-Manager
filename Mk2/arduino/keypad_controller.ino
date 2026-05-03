/*
 * keypad_controller.ino — Arduino Mega Keypad Controller
 *
 * Hardware:
 *   - Arduino Mega 2560
 *   - 4x4 Matrix Keypad
 *   - Green LED (pin 22)
 *   - Yellow LED (pin 24)
 *   - Red LED (pin 26)
 *
 * Behavior:
 *   - Reads 6-digit PIN from keypad.
 *   - Sends "PIN_ATTEMPT:XXXXXX" to Python backend over serial.
 *   - Waits for response: GRANTED, DENIED, PENDING, or LOCKED.
 *   - Controls LEDs based on response.
 *
 * NOTE: The Arduino does NO cryptography or database logic.
 *       It is a simple I/O device controlled by the Python backend.
 */

#include <Keypad.h>

// -----------------
// Pin Definitions |
// -----------------

const int GREEN_LED  = 22;
const int YELLOW_LED = 24;
const int RED_LED    = 26;

// ----------------------
// Keypad Configuration |
// ----------------------

const byte ROWS = 4;
const byte COLS = 4;

char keys[ROWS][COLS] = {
    {'1', '2', '3', 'A'},
    {'4', '5', '6', 'B'},
    {'7', '8', '9', 'C'},
    {'*', '0', '#', 'D'}
};

// TODO: Update these pin assignments for your wiring
byte rowPins[ROWS] = {34, 36, 38, 40};
byte colPins[COLS] = {42, 44, 46, 48};

Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

// -------
// State |
// -------

const int PIN_LENGTH = 6;
char pinBuffer[PIN_LENGTH + 1];
int pinIndex = 0;

// -------
// Setup |
// -------

void setup() {
    Serial.begin(9600);

    pinMode(GREEN_LED, OUTPUT);
    pinMode(YELLOW_LED, OUTPUT);
    pinMode(RED_LED, OUTPUT);

    resetLEDs();
    clearPinBuffer();

    Serial.println("KEYPAD_READY");
}

// -----------
// Main Loop |
// -----------

void loop() {
    char key = keypad.getKey();

    if (key) {
        handleKeyPress(key);
    }

    if (Serial.available() > 0) {
        String response = Serial.readStringUntil('\n');
        response.trim();
        handleResponse(response);
    }
}

// -------------------
// Key Press Handler | 
// -------------------

void handleKeyPress(char key) {
    /*
     * Behavior:
     *   - '#' = Submit PIN (if 6 digits entered)
     *   - '*' = Clear / cancel current PIN entry
     *   - '0'-'9' = Append digit to PIN buffer
     *   - 'A'-'D' = Ignore (reserved for future special functions)
     *
     * When PIN is complete (6 digits + '#'):
     *   1. Send "PIN_ATTEMPT:XXXXXX" over serial.
     *   2. Flash yellow LED briefly to indicate sending.
     *   3. Clear the PIN buffer.
     */

    if (key == '*') {
        // Clear / cancel: reset the buffer and LEDs
        clearPinBuffer();
        resetLEDs();
        Serial.println("PIN_CLEARED");
        return;
    }

    if (key == '#') {
        // Submit: only if we have exactly 6 digits
        if (pinIndex == PIN_LENGTH) {
            // Flash yellow to indicate transmission
            setYellow();

            // Send the PIN attempt to the Python backend
            Serial.print("PIN_ATTEMPT:");
            Serial.println(pinBuffer);

            // Clear the buffer for the next attempt
            clearPinBuffer();

            // Brief yellow flash, then turn off
            // (response handler will set the final LED state)
            delay(200);
            resetLEDs();
        } else {
            // Not enough digits — flash red briefly as feedback
            flashRed(300);
        }
        return;
    }

    if (key >= 'A' && key <= 'D') {
        // Ignore letter keys (reserved for future use)
        return;
    }

    // Digit key: '0'-'9'
    if (key >= '0' && key <= '9') {
        if (pinIndex < PIN_LENGTH) {
            pinBuffer[pinIndex] = key;
            pinIndex++;
            // Acknowledge digit with a brief yellow blink
            digitalWrite(YELLOW_LED, HIGH);
            delay(50);
            digitalWrite(YELLOW_LED, LOW);
        }
        // If already at 6 digits, ignore further digits until '#' or '*'
    }
}

// ------------------
// Response Handler |
// ------------------

void handleResponse(String response) {
    /*
     * Expected responses from Python backend:
     *   "GRANTED"  → Turn on GREEN LED, turn off others.
     *   "DENIED"   → Flash RED LED for 2 seconds, then reset.
     *   "PENDING"  → Turn on YELLOW LED (passphrase window open).
     *   "LOCKED"   → Reset all LEDs.
     */

    if (response == "GRANTED") {
        setGreen();
    }
    else if (response == "DENIED") {
        flashRed(2000);
    }
    else if (response == "PENDING") {
        setYellow();
    }
    else if (response == "LOCKED") {
        resetLEDs();
    }
    // Unknown responses are silently ignored
}

// -------------
// LED Control |
// -------------

void resetLEDs() {
    digitalWrite(GREEN_LED, LOW);
    digitalWrite(YELLOW_LED, LOW);
    digitalWrite(RED_LED, LOW);
}

void setGreen() {
    resetLEDs();
    digitalWrite(GREEN_LED, HIGH);
}

void setYellow() {
    resetLEDs();
    digitalWrite(YELLOW_LED, HIGH);
}

void setRed() {
    resetLEDs();
    digitalWrite(RED_LED, HIGH);
}

void flashRed(unsigned long duration) {
    setRed();
    delay(duration);
    resetLEDs();
}

// ------------
// PIN Buffer |
// ------------

void clearPinBuffer() {
    memset(pinBuffer, 0, sizeof(pinBuffer));
    pinIndex = 0;
}
