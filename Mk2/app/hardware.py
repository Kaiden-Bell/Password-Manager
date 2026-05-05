"""
hardware.py — Hardware authentication logic.

Bridges serial_service and auth for PIN validation and LED status responses.
"""

from app import serial_service, auth

# --------------
# PIN Handling |
# --------------

def handle_pin_attempt(pin_attempt: str) -> str:
    """
        Desc: Process a PIN attempt received from the Arduino.
        Arguments: pin_attempt
        Returns: str
    """
    from app import database
    vaults = database.get_all_vaults()
    
    for v in vaults:
        vault_id = v["vault_id"]
        policy = database.load_vault_policy(vault_id)
        if policy and policy.get("hardware_gate_required"):
            if auth.verify_hardware_pin(vault_id, pin_attempt):
                send_granted()
                return "GRANTED"
                
    send_denied()
    return "DENIED"

# -------------------
# Arduino Responses |
# -------------------

def send_granted() -> None:
    """
        Desc: Send GRANTED to Arduino: green LED on.
        Arguments: None
        Returns: None
    """
    serial_service.send_message("GRANTED")

def send_denied() -> None:
    """
        Desc: Send DENIED to Arduino: red LED on.
        Arguments: None
        Returns: None
    """
    serial_service.send_message("DENIED")

def send_pending() -> None:
    """
        Desc: Send PENDING to Arduino: yellow LED on.
        Arguments: None
        Returns: None
    """
    serial_service.send_message("PENDING")

def send_locked() -> None:
    """
        Desc: Send LOCKED to Arduino: all LEDs reset.
        Arguments: None
        Returns: None
    """
    serial_service.send_message("LOCKED")
