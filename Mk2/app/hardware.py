"""
hardware.py — Hardware authentication logic.

Bridges serial_service (raw I/O) and auth (vault logic).
Handles PIN validation flow and LED status responses.
"""

from app import serial_service, auth


# --------------
# PIN Handling |
# --------------

def handle_pin_attempt(pin_attempt: str) -> str:
    """
        Desc: Process a PIN attempt received from the Arduino.
        Args: pin_attempt
        Return: str
    """
    vault_id = 1  # For MVP, assume vault_id=1
    is_valid = auth.verify_hardware_pin(vault_id, pin_attempt)

    if is_valid:
        send_pending()
        return "PENDING"
    else:
        send_denied()
        return "DENIED"


# -------------------
# Arduino Responses |
# -------------------

def send_granted() -> None:
    """
        Desc: Send GRANTED to Arduino: green LED on.
        Args: None
        Return: None
    """
    serial_service.send_message("GRANTED")


def send_denied() -> None:
    """
        Desc: Send DENIED to Arduino: red LED on.
        Args: None
        Return: None
    """
    serial_service.send_message("DENIED")


def send_pending() -> None:
    """
        Desc: Send PENDING to Arduino: yellow LED on.
        Args: None
        Return: None
    """
    serial_service.send_message("PENDING")


def send_locked() -> None:
    """
        Desc: Send LOCKED to Arduino: all LEDs reset.
        Args: None
        Return: None
    """
    serial_service.send_message("LOCKED")
