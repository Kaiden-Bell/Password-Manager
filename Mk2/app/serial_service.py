"""
serial_service.py — Raw Arduino serial communication.

Handles the low-level serial port connection to the Arduino.
Runs a background listener thread that reads messages and dispatches
them to the hardware module.
"""

import threading
import time

import serial

from app.config import SERIAL_PORT, BAUD_RATE


# --------------
# Module State |
# --------------

_serial_connection = None        # serial.Serial instance
_listener_thread: threading.Thread | None = None
_running = False


# -----------------------
# Connection Management |
# -----------------------

def connect(port: str = SERIAL_PORT, baud: int = BAUD_RATE) -> bool:
    """
        Desc: Open the serial connection to the Arduino.
        Args:
            port: Serial port path (e.g., "/dev/ttyACM0" or "COM3").
            baud: Baud rate (default 9600).
        Returns: True if connection was successful.
    """
    global _serial_connection

    try:
        _serial_connection = serial.Serial(port, baud, timeout=1)
        time.sleep(2)
        return True
    except serial.SerialException as e:
        print(f"[serial_service] Connection failed: {e}")
        _serial_connection = None
        return False


def disconnect() -> None:
    """
        Desc: Close the serial connection and stop the listener thread.
    """
    global _serial_connection, _running

    _running = False

    if _listener_thread is not None:
        _listener_thread.join(timeout=3)

    if _serial_connection is not None and _serial_connection.is_open:
        _serial_connection.close()
        _serial_connection = None


# -------------
# Message I/O |
# -------------

def read_message() -> str | None:
    """
        Desc: Read one line from the serial port.
        Returns: Decoded message string (stripped), or None if no data.
    """
    if _serial_connection is None or not _serial_connection.is_open: return None

    try:
        raw = _serial_connection.readline()
        if raw:
            message = raw.decode("utf-8").strip()
            return message if message else None
        return None
    except (serial.SerialException, UnicodeDecodeError) as e:
        print(f"[serial_service] Read error: {e}")
        return None


def send_message(message: str) -> None:
    """
        Desc: Send a response message to the Arduino.
        Args: message: One of "GRANTED", "DENIED", "PENDING", "LOCKED".
    """
    if _serial_connection is None or not _serial_connection.is_open:
        print(f"[serial_service] Cannot send '{message}': no connection")
        return

    try:
        _serial_connection.write((message + "\n").encode("utf-8"))
        _serial_connection.flush()
    except serial.SerialException as e:
        print(f"[serial_service] Write error: {e}")


# ---------------------
# Background Listener |
# ---------------------

def start_serial_listener(on_pin_attempt=None) -> None:
    """
        Desc: Start a background thread that continuously reads from the serial port.
        Args: on_pin_attempt: Callback function that receives a PIN string, called when a valid PIN_ATTEMPT message is parsed.
    """
    global _listener_thread, _running

    if _running: return

    _running = True

    def _listener_loop():
        while _running:
            message = read_message()
            if message:
                pin = parse_pin_attempt(message)
                if pin and on_pin_attempt:
                    on_pin_attempt(pin)

    _listener_thread = threading.Thread(target=_listener_loop, daemon=True)
    _listener_thread.start()


# -----------------
# Message Parsing |
# -----------------

def parse_pin_attempt(message: str) -> str | None:
    """
        Desc: Parse a PIN attempt from an Arduino message.
        Args: message: Raw message from Arduino.
        Returns: The 6-digit PIN string, or None if the message doesn't match.
    """
    prefix = "PIN_ATTEMPT:"
    if not message.startswith(prefix): return None

    pin = message[len(prefix):]

    if len(pin) == 6 and pin.isdigit():
        return pin

    return None
