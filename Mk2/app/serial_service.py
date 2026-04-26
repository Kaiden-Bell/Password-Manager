"""
serial_service.py — Raw Arduino serial communication.

Handles the low-level serial port connection to the Arduino.
Runs a background listener thread that reads messages and dispatches
them to the hardware module.

Expected Arduino messages:
    PIN_ATTEMPT:122004

Expected backend responses:
    GRANTED | DENIED | PENDING | LOCKED
"""

import threading

# import serial  # pyserial

from app.config import SERIAL_PORT, BAUD_RATE


# ═══════════════════════════════════════════════════════════════════════════
# Module State
# ═══════════════════════════════════════════════════════════════════════════

_serial_connection = None        # serial.Serial instance
_listener_thread: threading.Thread | None = None
_running = False


# ═══════════════════════════════════════════════════════════════════════════
# Connection Management
# ═══════════════════════════════════════════════════════════════════════════

def connect(port: str = SERIAL_PORT, baud: int = BAUD_RATE) -> bool:
    """
    Open the serial connection to the Arduino.

    Args:
        port: Serial port path (e.g., "/dev/ttyACM0" or "COM3").
        baud: Baud rate (default 9600).

    Returns:
        True if connection was successful.

    TODO:
        1. Create serial.Serial(port, baud, timeout=1).
        2. Store in _serial_connection.
        3. Handle serial.SerialException gracefully.
    """
    raise NotImplementedError("connect")


def disconnect() -> None:
    """
    Close the serial connection.

    TODO:
        1. Stop the listener thread (_running = False).
        2. Close _serial_connection if open.
    """
    raise NotImplementedError("disconnect")


# ═══════════════════════════════════════════════════════════════════════════
# Message I/O
# ═══════════════════════════════════════════════════════════════════════════

def read_message() -> str | None:
    """
    Read one line from the serial port.

    Returns:
        Decoded message string (stripped), or None if no data.

    TODO:
        1. Read a line from _serial_connection.
        2. Decode as UTF-8.
        3. Strip whitespace.
        4. Return None if empty or if connection is not open.
    """
    raise NotImplementedError("read_message")


def send_message(message: str) -> None:
    """
    Send a response message to the Arduino.

    Args:
        message: One of "GRANTED", "DENIED", "PENDING", "LOCKED".

    TODO:
        1. Encode message as UTF-8 with newline.
        2. Write to _serial_connection.
    """
    raise NotImplementedError("send_message")


# ═══════════════════════════════════════════════════════════════════════════
# Background Listener
# ═══════════════════════════════════════════════════════════════════════════

def start_serial_listener(on_pin_attempt=None) -> None:
    """
    Start a background thread that continuously reads from the serial port.

    Args:
        on_pin_attempt: Callback function that receives a PIN string.
                        Called when a valid PIN_ATTEMPT message is parsed.

    TODO:
        1. Set _running = True.
        2. Start a daemon thread that loops:
           a. Call read_message().
           b. Call parse_pin_attempt() on the message.
           c. If a valid PIN is parsed, call on_pin_attempt(pin).
    """
    raise NotImplementedError("start_serial_listener")


# ═══════════════════════════════════════════════════════════════════════════
# Message Parsing
# ═══════════════════════════════════════════════════════════════════════════

def parse_pin_attempt(message: str) -> str | None:
    """
    Parse a PIN attempt from an Arduino message.

    Expected format: "PIN_ATTEMPT:XXXXXX"

    Args:
        message: Raw message from Arduino.

    Returns:
        The 6-digit PIN string, or None if the message doesn't match.

    TODO:
        1. Check if message starts with "PIN_ATTEMPT:".
        2. Extract the PIN portion.
        3. Validate it is exactly 6 digits.
        4. Return the PIN or None.
    """
    raise NotImplementedError("parse_pin_attempt")
