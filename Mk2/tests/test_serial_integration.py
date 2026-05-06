"""
test_serial_integration.py — End-to-end serial integration tests.

Tests the full hardware PIN flow WITHOUT real Arduino hardware by mocking
the serial port. Verifies:
    1. serial_service: parse_pin_attempt, message parsing, connect/disconnect
    2. hardware: handle_pin_attempt dispatches correct responses
    3. auth: verify_hardware_pin validates/rejects PINs
    4. session: passphrase window opens on valid PIN
    5. Full unlock: PIN → passphrase window → passphrase → vault decrypted
    6. Lockout: 3 failed PIN attempts → vault locked
"""

import os
import sys
import sqlite3
import time
import pytest
from unittest.mock import patch, MagicMock

# -----------
# Fixtures  |
# -----------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """
    Redirect DATABASE_PATH to a temp SQLite file and initialize the schema.
    """
    db_path = str(tmp_path / "test_vault.db")
    monkeypatch.setattr("app.config.DATABASE_PATH", db_path)
    monkeypatch.setattr("app.database.DATABASE_PATH", db_path)
    
    from app.database import db
    db.initialize_database()
    yield db_path


@pytest.fixture(autouse=True)
def clean_sessions():
    """
    Clear all sessions and passphrase windows before/after each test.
    """
    from app import session
    session._sessions.clear()
    session._passphrase_windows.clear()
    yield
    session._sessions.clear()
    session._passphrase_windows.clear()


@pytest.fixture
def initialized_vault():
    """
    Create a fully initialized vault with PIN and passphrase for testing.
    Returns a dict with vault_id, user_id, passphrase, and pin.
    """
    from app import auth

    passphrase = "TestPassphrase!123"
    pin = "122004"

    result = auth.initialize_vault(
        username="testuser",
        display_name="Test User",
        vault_name="Test Vault",
        passphrase=passphrase,
        keypad_pin=pin,
        hardware_gate_required=True,
        software_only_enabled=True,
    )

    return {
        "vault_id": result["vault_id"],
        "user_id": result["user_id"],
        "passphrase": passphrase,
        "pin": pin,
    }


# ═══════════════════════════════════════════════════════════════════════════
# 1. serial_service.parse_pin_attempt
# ═══════════════════════════════════════════════════════════════════════════

class TestParsePinAttempt:
    """Test message parsing from Arduino serial output."""

    def test_valid_pin(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("PIN_ATTEMPT:122004") == "122004"

    def test_valid_pin_all_zeros(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("PIN_ATTEMPT:000000") == "000000"

    def test_valid_pin_all_nines(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("PIN_ATTEMPT:999999") == "999999"

    def test_too_short(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("PIN_ATTEMPT:12345") is None

    def test_too_long(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("PIN_ATTEMPT:1234567") is None

    def test_non_digits(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("PIN_ATTEMPT:12AB34") is None

    def test_wrong_prefix(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("KEY:5") is None

    def test_keypad_ready(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("KEYPAD_READY") is None

    def test_empty_string(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("") is None

    def test_pin_cleared(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("PIN_CLEARED") is None

    def test_no_pin_value(self):
        from app.serial_service import parse_pin_attempt
        assert parse_pin_attempt("PIN_ATTEMPT:") is None


# ═══════════════════════════════════════════════════════════════════════════
# 2. serial_service connect/disconnect (mocked serial port)
# ═══════════════════════════════════════════════════════════════════════════

class TestSerialConnection:
    """Test serial connect/disconnect with mocked pyserial."""

    @patch("app.serial_service.serial.Serial")
    @patch("app.serial_service.time.sleep")
    def test_connect_success(self, mock_sleep, mock_serial_class):
        from app import serial_service

        mock_serial_instance = MagicMock()
        mock_serial_class.return_value = mock_serial_instance

        # Reset module state
        serial_service._serial_connection = None

        result = serial_service.connect("/dev/ttyTEST", 9600)

        assert result is True
        mock_serial_class.assert_called_once_with("/dev/ttyTEST", 9600, timeout=1)
        assert serial_service._serial_connection is mock_serial_instance

        # Cleanup
        serial_service._serial_connection = None

    @patch("app.serial_service.serial.Serial")
    def test_connect_failure(self, mock_serial_class):
        import serial as pyserial
        from app import serial_service

        mock_serial_class.side_effect = pyserial.SerialException("Port not found")
        serial_service._serial_connection = None

        result = serial_service.connect("/dev/ttyNONE", 9600)

        assert result is False
        assert serial_service._serial_connection is None

    @patch("app.serial_service.serial.Serial")
    @patch("app.serial_service.time.sleep")
    def test_disconnect(self, mock_sleep, mock_serial_class):
        from app import serial_service

        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_serial_class.return_value = mock_conn

        serial_service._serial_connection = None
        serial_service.connect("/dev/ttyTEST", 9600)

        serial_service.disconnect()

        mock_conn.close.assert_called_once()
        assert serial_service._serial_connection is None


# ═══════════════════════════════════════════════════════════════════════════
# 3. serial_service send/read messages (mocked)
# ═══════════════════════════════════════════════════════════════════════════

class TestSerialMessaging:
    """Test message I/O with mocked serial connection."""

    def test_send_message(self):
        from app import serial_service

        mock_conn = MagicMock()
        mock_conn.is_open = True
        serial_service._serial_connection = mock_conn

        serial_service.send_message("GRANTED")

        mock_conn.write.assert_called_once_with(b"GRANTED\n")
        mock_conn.flush.assert_called_once()

        serial_service._serial_connection = None

    def test_send_denied(self):
        from app import serial_service

        mock_conn = MagicMock()
        mock_conn.is_open = True
        serial_service._serial_connection = mock_conn

        serial_service.send_message("DENIED")
        mock_conn.write.assert_called_once_with(b"DENIED\n")

        serial_service._serial_connection = None

    def test_send_no_connection(self, capsys):
        from app import serial_service
        serial_service._serial_connection = None

        serial_service.send_message("GRANTED")

        captured = capsys.readouterr()
        assert "Cannot send" in captured.out

    def test_read_message(self):
        from app import serial_service

        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_conn.readline.return_value = b"PIN_ATTEMPT:122004\r\n"
        serial_service._serial_connection = mock_conn

        result = serial_service.read_message()
        assert result == "PIN_ATTEMPT:122004"

        serial_service._serial_connection = None

    def test_read_empty(self):
        from app import serial_service

        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_conn.readline.return_value = b""
        serial_service._serial_connection = mock_conn

        result = serial_service.read_message()
        assert result is None

        serial_service._serial_connection = None

    def test_read_no_connection(self):
        from app import serial_service
        serial_service._serial_connection = None

        result = serial_service.read_message()
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# 4. hardware.handle_pin_attempt (with mocked serial_service.send_message)
# ═══════════════════════════════════════════════════════════════════════════

class TestHandlePinAttempt:
    """Test the hardware module PIN dispatch logic."""

    @patch("app.serial_service.send_message")
    def test_valid_pin_returns_pending(self, mock_send, initialized_vault):
        from app import hardware

        result = hardware.handle_pin_attempt(initialized_vault["pin"])
        assert result == "PENDING"
        mock_send.assert_called_once_with("PENDING")

    @patch("app.serial_service.send_message")
    def test_invalid_pin_returns_denied(self, mock_send, initialized_vault):
        from app import hardware

        result = hardware.handle_pin_attempt("000000")
        assert result == "DENIED"
        mock_send.assert_called_once_with("DENIED")

    @patch("app.serial_service.send_message")
    def test_wrong_length_pin_returns_denied(self, mock_send, initialized_vault):
        from app import hardware

        result = hardware.handle_pin_attempt("123")
        assert result == "DENIED"
        mock_send.assert_called_once_with("DENIED")


# ═══════════════════════════════════════════════════════════════════════════
# 5. auth.verify_hardware_pin — PIN validation + passphrase window
# ═══════════════════════════════════════════════════════════════════════════

class TestVerifyHardwarePin:
    """Test PIN verification and passphrase window lifecycle."""

    def test_correct_pin_opens_passphrase_window(self, initialized_vault):
        from app import auth, session

        result = auth.verify_hardware_pin(
            initialized_vault["vault_id"],
            initialized_vault["pin"]
        )

        assert result is True
        assert session.is_passphrase_window_active(initialized_vault["vault_id"]) is True

    def test_wrong_pin_does_not_open_window(self, initialized_vault):
        from app import auth, session

        result = auth.verify_hardware_pin(
            initialized_vault["vault_id"],
            "000000"
        )

        assert result is False
        assert session.is_passphrase_window_active(initialized_vault["vault_id"]) is False

    def test_failed_attempts_increment(self, initialized_vault):
        from app import auth
from app.database import db

        for _ in range(2):
            auth.verify_hardware_pin(initialized_vault["vault_id"], "999999")

        attempts = db.get_failed_pin_attempts(initialized_vault["vault_id"])
        assert attempts == 2

    def test_correct_pin_resets_failed_attempts(self, initialized_vault):
        from app import auth
from app.database import db

        # Fail twice
        auth.verify_hardware_pin(initialized_vault["vault_id"], "999999")
        auth.verify_hardware_pin(initialized_vault["vault_id"], "999999")

        # Succeed
        auth.verify_hardware_pin(initialized_vault["vault_id"], initialized_vault["pin"])

        attempts = db.get_failed_pin_attempts(initialized_vault["vault_id"])
        assert attempts == 0


# ═══════════════════════════════════════════════════════════════════════════
# 6. Lockout after 3 failed attempts
# ═══════════════════════════════════════════════════════════════════════════

class TestPinLockout:
    """Test that 3 consecutive failed PINs lock the vault."""

    def test_lockout_after_three_failures(self, initialized_vault):
        from app import auth
from app.database import db

        for _ in range(3):
            auth.verify_hardware_pin(initialized_vault["vault_id"], "000000")

        vault = db.load_vault(initialized_vault["vault_id"])
        assert vault["vault_status"] == "LOCKED"

    def test_fourth_attempt_still_locked(self, initialized_vault):
        from app import auth
from app.database import db

        # Trigger lockout
        for _ in range(3):
            auth.verify_hardware_pin(initialized_vault["vault_id"], "000000")

        # Even with correct PIN, vault status stays locked in DB
        result = auth.verify_hardware_pin(
            initialized_vault["vault_id"],
            initialized_vault["pin"]
        )
        # verify_hardware_pin still checks the hash, 
        # but the vault status in DB should be LOCKED
        vault = db.load_vault(initialized_vault["vault_id"])
        assert vault["vault_status"] == "LOCKED"


# ═══════════════════════════════════════════════════════════════════════════
# 7. Full end-to-end: PIN → Passphrase Window → Unlock → Session
# ═══════════════════════════════════════════════════════════════════════════

class TestFullUnlockFlow:
    """Test the complete hardware-gated unlock sequence."""

    def test_hardware_gated_unlock(self, initialized_vault):
        """
        Full flow:
            1. Verify PIN → passphrase window opens
            2. Unlock with passphrase → session created
            3. Session is active and vault data is decrypted
        """
        from app import auth, session

        # Step 1: PIN opens passphrase window
        pin_ok = auth.verify_hardware_pin(
            initialized_vault["vault_id"],
            initialized_vault["pin"]
        )
        assert pin_ok is True
        assert session.is_passphrase_window_active(initialized_vault["vault_id"])

        # Step 2: Unlock with passphrase (hardware-gated)
        result = auth.unlock_with_passphrase(
            initialized_vault["vault_id"],
            initialized_vault["passphrase"]
        )
        assert result["success"] is True

        # Step 3: Session should be active
        assert session.is_unlocked(initialized_vault["vault_id"]) is True
        sess = session.get_session(initialized_vault["vault_id"])
        assert sess is not None
        assert sess["is_unlocked"] is True
        assert sess["active_vault_id"] == initialized_vault["vault_id"]
        assert "decrypted_vault" in sess
        assert sess["decrypted_vault"]["entries"] == []
        assert sess["vault_master_key"] is not None

    def test_software_only_unlock(self, initialized_vault):
        """Software-only unlock bypass (no PIN needed)."""
        from app import auth, session

        result = auth.unlock_software_only(
            initialized_vault["vault_id"],
            initialized_vault["passphrase"]
        )
        assert result["success"] is True
        assert session.is_unlocked(initialized_vault["vault_id"]) is True

    def test_wrong_passphrase_fails(self, initialized_vault):
        """Wrong passphrase should raise CryptoError."""
        from app import auth, session
        from nacl.exceptions import CryptoError

        # Open passphrase window first
        auth.verify_hardware_pin(
            initialized_vault["vault_id"],
            initialized_vault["pin"]
        )

        with pytest.raises(CryptoError):
            auth.unlock_with_passphrase(
                initialized_vault["vault_id"],
                "WrongPassphrase!999"
            )

    def test_passphrase_without_window_fails(self, initialized_vault):
        """Attempting passphrase unlock without PIN first should fail."""
        from app import auth

        with pytest.raises(ValueError, match="Passphrase window is not active"):
            auth.unlock_with_passphrase(
                initialized_vault["vault_id"],
                initialized_vault["passphrase"]
            )


# ═══════════════════════════════════════════════════════════════════════════
# 8. Simulated serial listener loop (background thread)
# ═══════════════════════════════════════════════════════════════════════════

class TestSerialListener:
    """Test the background serial listener dispatches correctly."""

    def test_listener_dispatches_pin(self):
        """Simulate the listener reading a PIN_ATTEMPT and calling the callback."""
        from app import serial_service

        received_pins = []

        def mock_callback(pin):
            received_pins.append(pin)

        # Simulate two reads: one PIN message, then empty forever
        read_count = 0
        original_running = serial_service._running

        def fake_read():
            nonlocal read_count
            read_count += 1
            if read_count == 1:
                return "PIN_ATTEMPT:543210"
            # Stop the loop after first message
            serial_service._running = False
            return None

        with patch.object(serial_service, "read_message", side_effect=fake_read):
            serial_service._running = True
            # Run the listener loop manually (not in thread)
            while serial_service._running:
                msg = serial_service.read_message()
                if msg:
                    pin = serial_service.parse_pin_attempt(msg)
                    if pin and mock_callback:
                        mock_callback(pin)

        assert received_pins == ["543210"]
        serial_service._running = original_running


# ═══════════════════════════════════════════════════════════════════════════
# 9. Full simulated hardware flow (keypad → serial → python → response)
# ═══════════════════════════════════════════════════════════════════════════

class TestSimulatedHardwareFlow:
    """
    Simulate the complete keypad → serial → Python → response cycle.
    This is what happens when someone presses keys on the physical keypad.
    """

    @patch("app.serial_service.send_message")
    def test_valid_pin_flow(self, mock_send, initialized_vault):
        """
        Simulate: User types 122004# on keypad.
        Arduino sends: "PIN_ATTEMPT:122004"
        Python receives → verifies → sends "PENDING" back.
        """
        from app import serial_service, hardware, session

        # Step 1: Arduino message arrives
        raw_message = "PIN_ATTEMPT:122004"
        pin = serial_service.parse_pin_attempt(raw_message)
        assert pin == "122004"

        # Step 2: hardware.handle_pin_attempt processes it
        response = hardware.handle_pin_attempt(pin)
        assert response == "PENDING"

        # Step 3: Python sends PENDING back to Arduino
        mock_send.assert_called_once_with("PENDING")

        # Step 4: Passphrase window is now open
        assert session.is_passphrase_window_active(initialized_vault["vault_id"])

    @patch("app.serial_service.send_message")
    def test_invalid_pin_flow(self, mock_send, initialized_vault):
        """
        Simulate: User types 999999# on keypad.
        Arduino sends: "PIN_ATTEMPT:999999"
        Python receives → rejects → sends "DENIED" back.
        """
        from app import serial_service, hardware, session

        raw_message = "PIN_ATTEMPT:999999"
        pin = serial_service.parse_pin_attempt(raw_message)
        assert pin == "999999"

        response = hardware.handle_pin_attempt(pin)
        assert response == "DENIED"
        mock_send.assert_called_once_with("DENIED")

        # Passphrase window should NOT be open
        assert session.is_passphrase_window_active(initialized_vault["vault_id"]) is False

    @patch("app.serial_service.send_message")
    def test_full_unlock_to_granted(self, mock_send, initialized_vault):
        """
        Full flow:
            1. PIN_ATTEMPT:122004 → PENDING
            2. Passphrase unlock → session created
            3. Send GRANTED to Arduino
        """
        from app import serial_service, hardware, auth, session

        # Step 1: Valid PIN
        pin = serial_service.parse_pin_attempt("PIN_ATTEMPT:122004")
        hardware.handle_pin_attempt(pin)

        # Step 2: Passphrase unlock
        auth.unlock_with_passphrase(
            initialized_vault["vault_id"],
            initialized_vault["passphrase"]
        )

        # Step 3: Verify session is active
        assert session.is_unlocked(initialized_vault["vault_id"])

        # Step 4: Send GRANTED (as the frontend/API would do)
        mock_send.reset_mock()
        hardware.send_granted()
        mock_send.assert_called_once_with("GRANTED")

    @patch("app.serial_service.send_message")
    def test_lockout_sends_locked(self, mock_send, initialized_vault):
        """
        3 failed PINs → vault locked → LOCKED could be sent to Arduino.
        """
        from app import serial_service, hardware
from app.database import db

        # Trigger 3 failures
        for _ in range(3):
            pin = serial_service.parse_pin_attempt("PIN_ATTEMPT:000000")
            hardware.handle_pin_attempt(pin)

        # Verify vault is locked
        vault = db.load_vault(initialized_vault["vault_id"])
        assert vault["vault_status"] == "LOCKED"

        # Send LOCKED response
        mock_send.reset_mock()
        hardware.send_locked()
        mock_send.assert_called_once_with("LOCKED")
