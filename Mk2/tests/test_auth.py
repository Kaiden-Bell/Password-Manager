"""
test_auth.py — Tests for the auth module.

Run with:
    python -m pytest tests/test_auth.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
import base64

from app.auth import (
    initialize_vault,
    verify_hardware_pin,
    open_passphrase_window,
    is_passphrase_window_active,
    unlock_with_passphrase,
    unlock_software_only,
)

class TestVaultInitialization:
    @patch("app.auth.database")
    @patch("app.auth.crypto")
    @patch("app.auth.vault")
    def test_initialize_creates_vault(self, mock_vault, mock_crypto, mock_db):
        mock_db.create_user.return_value = 1
        mock_db.create_vault.return_value = 42
        mock_crypto.generate_salt.return_value = b"salt"
        mock_crypto.wrap_master_key.return_value = ("wrapped", "nonce")
        mock_crypto.encrypt_xchacha20_poly1305.return_value = ("enc_blob", "enc_nonce")
        mock_vault.create_empty_vault.return_value = {"entries": []}
        
        result = initialize_vault("user", "Display", "Vault", "pass", keypad_pin="1234")
        
        assert result["success"] is True
        assert result["vault_id"] == 42
        mock_db.create_user.assert_called_once()
        mock_db.create_vault.assert_called_once()
        mock_db.create_vault_policy.assert_called_once()
        mock_db.save_auth_credentials.assert_called_once()
        mock_db.save_hardware_auth.assert_called_once()
        mock_db.save_vault_data.assert_called_once()


class TestSoftwareOnlyUnlock:
    @patch("app.auth.database")
    @patch("app.auth.crypto")
    @patch("app.auth.session")
    @patch("app.auth.vault")
    def test_correct_passphrase_unlocks(self, mock_vault, mock_session, mock_crypto, mock_db):
        mock_db.load_vault_policy.return_value = {"software_only_enabled": True}
        mock_db.load_auth_credentials.return_value = {
            "passphrase_salt": base64.b64encode(b"salt").decode("utf-8"),
            "wrapped_master_key": "wrapped",
            "wrapped_master_key_nonce": "nonce",
            "kdf_memory_cost": 1024,
            "kdf_time_cost": 2,
            "kdf_parallelism": 1
        }
        mock_crypto.unwrap_master_key.return_value = b"master_key"
        
        result = unlock_software_only(42, "correct_pass")
        
        assert result["success"] is True
        mock_session.create_session.assert_called_once()

    @patch("app.auth.database")
    def test_software_only_disabled_fails(self, mock_db):
        mock_db.load_vault_policy.return_value = {"software_only_enabled": False}
        with pytest.raises(ValueError, match="not enabled"):
            unlock_software_only(42, "pass")


class TestHardwareGatedUnlock:
    @patch("app.auth.database")
    @patch("app.auth.crypto")
    @patch("app.auth.session")
    def test_correct_pin_opens_window(self, mock_session, mock_crypto, mock_db):
        mock_db.load_hardware_auth.return_value = {
            "keypad_pin_salt": base64.b64encode(b"salt").decode("utf-8"),
            "keypad_pin_hash": "hash"
        }
        mock_crypto.verify_keypad_pin.return_value = True
        
        result = verify_hardware_pin(42, "1234")
        
        assert result is True
        mock_session.open_passphrase_window.assert_called_once_with(42)

    @patch("app.auth.database")
    @patch("app.auth.crypto")
    def test_wrong_pin_denied(self, mock_crypto, mock_db):
        mock_db.load_hardware_auth.return_value = {
            "keypad_pin_salt": base64.b64encode(b"salt").decode("utf-8"),
            "keypad_pin_hash": "hash"
        }
        mock_crypto.verify_keypad_pin.return_value = False
        mock_db.get_failed_pin_attempts.return_value = 1
        
        result = verify_hardware_pin(42, "9999")
        
        assert result is False
        mock_db.increment_failed_pin_attempts.assert_called_once()

    @patch("app.auth.session")
    def test_unlock_without_window_fails(self, mock_session):
        mock_session.is_passphrase_window_active.return_value = False
        with pytest.raises(ValueError, match="not active"):
            unlock_with_passphrase(42, "pass")
