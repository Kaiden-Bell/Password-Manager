"""
hardware.py — Hardware authentication logic.

Bridges serial_service (raw I/O) and auth (vault logic).
Handles PIN validation flow and LED status responses.

Flow:
    1. Receive PIN attempt from serial listener.
    2. Verify against database via auth.verify_hardware_pin().
    3. If valid  → open passphrase window, send PENDING.
    4. If invalid → send DENIED.
    5. On successful unlock → send GRANTED.
    6. On lock → send LOCKED.
"""

# from app import serial_service, auth


# ═══════════════════════════════════════════════════════════════════════════
# PIN Handling
# ═══════════════════════════════════════════════════════════════════════════

def handle_pin_attempt(pin_attempt: str) -> str:
    """
    Process a PIN attempt received from the Arduino.

    Steps:
        1. Look up the active vault (for MVP, assume vault_id=1).
        2. Call auth.verify_hardware_pin(vault_id, pin_attempt).
        3. If valid:
           a. Call send_pending().
           b. Return "PENDING".
        4. If invalid:
           a. Call send_denied().
           b. Return "DENIED".

    Returns:
        Status string: "PENDING" or "DENIED".

    TODO: Implement the PIN handling flow.
    """
    raise NotImplementedError("handle_pin_attempt")


# ═══════════════════════════════════════════════════════════════════════════
# Arduino Responses
# ═══════════════════════════════════════════════════════════════════════════

def send_granted() -> None:
    """
    Send GRANTED to Arduino → green LED on.

    TODO: Call serial_service.send_message("GRANTED").
    """
    raise NotImplementedError("send_granted")


def send_denied() -> None:
    """
    Send DENIED to Arduino → red LED on.

    TODO: Call serial_service.send_message("DENIED").
    """
    raise NotImplementedError("send_denied")


def send_pending() -> None:
    """
    Send PENDING to Arduino → yellow LED on.

    TODO: Call serial_service.send_message("PENDING").
    """
    raise NotImplementedError("send_pending")


def send_locked() -> None:
    """
    Send LOCKED to Arduino → all LEDs reset.

    TODO: Call serial_service.send_message("LOCKED").
    """
    raise NotImplementedError("send_locked")
