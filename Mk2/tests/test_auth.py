"""
test_auth.py — Tests for the auth module.

Run with:
    python -m pytest tests/test_auth.py -v
"""

import pytest


class TestVaultInitialization:
    """Tests for initialize_vault()."""

    def test_initialize_creates_user(self):
        """Should create a user in the database."""
        pytest.skip("Not implemented")

    def test_initialize_creates_vault(self):
        """Should create a vault row."""
        pytest.skip("Not implemented")

    def test_initialize_creates_policy(self):
        """Should create vault_policy with correct settings."""
        pytest.skip("Not implemented")

    def test_initialize_stores_auth_credentials(self):
        """Should store wrapped master key and salt."""
        pytest.skip("Not implemented")

    def test_initialize_with_pin(self):
        """Should store hashed keypad PIN when provided."""
        pytest.skip("Not implemented")

    def test_initialize_creates_encrypted_vault(self):
        """Should store an encrypted empty vault blob."""
        pytest.skip("Not implemented")


class TestSoftwareOnlyUnlock:
    """Tests for unlock_software_only()."""

    def test_correct_passphrase_unlocks(self):
        """Correct passphrase should unlock the vault."""
        pytest.skip("Not implemented")

    def test_wrong_passphrase_fails(self):
        """Wrong passphrase should raise CryptoError."""
        pytest.skip("Not implemented")

    def test_software_only_disabled_fails(self):
        """Should reject if software_only_enabled is False."""
        pytest.skip("Not implemented")


class TestHardwareGatedUnlock:
    """Tests for verify_hardware_pin() and unlock_with_passphrase()."""

    def test_correct_pin_opens_window(self):
        """Valid PIN should open the passphrase window."""
        pytest.skip("Not implemented")

    def test_wrong_pin_denied(self):
        """Invalid PIN should return False."""
        pytest.skip("Not implemented")

    def test_unlock_without_window_fails(self):
        """Passphrase unlock without active window should fail."""
        pytest.skip("Not implemented")

    def test_unlock_with_active_window_succeeds(self):
        """Passphrase unlock with active window should succeed."""
        pytest.skip("Not implemented")
