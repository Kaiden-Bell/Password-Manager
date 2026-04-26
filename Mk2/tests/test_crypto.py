"""
test_crypto.py — Tests for the crypto module.

Run with:
    python -m pytest tests/test_crypto.py -v
"""

import pytest


class TestKeyGeneration:
    """Tests for salt, nonce, and master key generation."""

    def test_generate_salt_returns_bytes(self):
        """Salt should be 16 bytes."""
        # TODO: from app.crypto import generate_salt
        # salt = generate_salt()
        # assert isinstance(salt, bytes)
        # assert len(salt) == 16
        pytest.skip("Not implemented")

    def test_generate_nonce_returns_bytes(self):
        """Nonce should be 24 bytes (XChaCha20)."""
        pytest.skip("Not implemented")

    def test_generate_master_key_returns_bytes(self):
        """Master key should be 32 bytes."""
        pytest.skip("Not implemented")

    def test_generate_salt_unique(self):
        """Two calls should produce different salts."""
        pytest.skip("Not implemented")


class TestArgon2Derivation:
    """Tests for Argon2id key derivation."""

    def test_derive_key_returns_correct_length(self):
        """Derived key should be KEY_LENGTH bytes."""
        pytest.skip("Not implemented")

    def test_derive_key_deterministic(self):
        """Same inputs should produce the same key."""
        pytest.skip("Not implemented")

    def test_derive_key_different_salt(self):
        """Different salts should produce different keys."""
        pytest.skip("Not implemented")

    def test_derive_key_different_passphrase(self):
        """Different passphrases should produce different keys."""
        pytest.skip("Not implemented")


class TestEncryptDecrypt:
    """Tests for XChaCha20-Poly1305 encrypt/decrypt."""

    def test_roundtrip(self):
        """Encrypt then decrypt should return original plaintext."""
        pytest.skip("Not implemented")

    def test_wrong_key_fails(self):
        """Decryption with wrong key should raise CryptoError."""
        pytest.skip("Not implemented")

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext should fail authentication."""
        pytest.skip("Not implemented")


class TestMasterKeyWrapping:
    """Tests for master key wrap/unwrap."""

    def test_wrap_unwrap_roundtrip(self):
        """Wrap then unwrap should return original master key."""
        pytest.skip("Not implemented")

    def test_wrong_wrapping_key_fails(self):
        """Unwrap with wrong key should raise CryptoError."""
        pytest.skip("Not implemented")


class TestPinHashing:
    """Tests for keypad PIN hash/verify."""

    def test_hash_and_verify(self):
        """Correct PIN should verify."""
        pytest.skip("Not implemented")

    def test_wrong_pin_fails(self):
        """Wrong PIN should not verify."""
        pytest.skip("Not implemented")
