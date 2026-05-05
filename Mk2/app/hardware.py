"""
hardware.py — Hardware authentication logic.

Bridges serial_service and auth for PIN validation and LED status responses.
"""

from app import serial_service, auth

# ---------------
# Module State  |
# ---------------

_target_vault_id: int | None = None

MAX_PASSPHRASE_ATTEMPTS = 3

_passphrase_fail_counts: dict[int, int] = {}

# ---------------
# Vault Context |
# ---------------

def set_target_vault(vault_id: int | None) -> None:
    """
        Desc: Set which vault the user is trying to unlock on the hardware keypad.
        Arguments: vault_id
        Returns: None
    """
    global _target_vault_id
    _target_vault_id = vault_id


def get_target_vault() -> int | None:
    """
        Desc: Get the vault_id the user has targeted for hardware unlock.
        Arguments: None
        Returns: int or None
    """
    return _target_vault_id

# -------------------------
# Passphrase Fail Counter |
# -------------------------

def get_passphrase_fail_count(vault_id: int) -> int:
    """
        Desc: Get current failed passphrase attempts for a vault.
        Arguments: vault_id
        Returns: int
    """
    return _passphrase_fail_counts.get(vault_id, 0)


def increment_passphrase_fail(vault_id: int) -> int:
    """
        Desc: Increment and return the failed passphrase count.
        Arguments: vault_id
        Returns: int, the new count
    """
    _passphrase_fail_counts[vault_id] = _passphrase_fail_counts.get(vault_id, 0) + 1
    return _passphrase_fail_counts[vault_id]


def reset_passphrase_fails(vault_id: int) -> None:
    """
        Desc: Reset the failed passphrase counter for a vault.
        Arguments: vault_id
        Returns: None
    """
    _passphrase_fail_counts.pop(vault_id, None)


def is_passphrase_locked_out(vault_id: int) -> bool:
    """
        Desc: Check if too many passphrase failures require re-PIN.
        Arguments: vault_id
        Returns: bool
    """
    return get_passphrase_fail_count(vault_id) >= MAX_PASSPHRASE_ATTEMPTS


# --------------
# PIN Handling |
# --------------

def handle_pin_attempt(pin_attempt: str) -> str:
    """
        Desc: Process a PIN attempt received from the Arduino.
        Arguments: pin_attempt
        Returns: str
    """
    if _target_vault_id is None:
        send_denied()
        return "DENIED"

    from app import database
    policy = database.load_vault_policy(_target_vault_id)
    if not policy or not policy.get("hardware_gate_required"):
        send_denied()
        return "DENIED"

    if auth.verify_hardware_pin(_target_vault_id, pin_attempt):
        # Reset passphrase fail counter on fresh PIN success
        reset_passphrase_fails(_target_vault_id)
        # Flash green once, then go to pending (waiting for passphrase)
        send_pin_ok()
        return "PIN_OK"

    send_denied()
    return "DENIED"

# -------------------
# Arduino Responses |
# -------------------

def send_pin_ok() -> None:
    """
        Desc: Send PIN_OK to Arduino: flash green briefly, then switch to yellow (pending).
        Arguments: None
        Returns: None
    """
    serial_service.send_message("PIN_OK")

def send_granted() -> None:
    """
        Desc: Send GRANTED to Arduino: flash green for a few seconds, then turn off.
        Arguments: None
        Returns: None
    """
    serial_service.send_message("GRANTED")

def send_denied() -> None:
    """
        Desc: Send DENIED to Arduino: red LED flash.
        Arguments: None
        Returns: None
    """
    serial_service.send_message("DENIED")

def send_passphrase_fail() -> None:
    """
        Desc: Send PASS_FAIL to Arduino: flash red briefly for wrong passphrase.
        Arguments: None
        Returns: None
    """
    serial_service.send_message("PASS_FAIL")

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
