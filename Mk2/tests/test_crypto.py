"""
test_crypto.py — Tests for the crypto module.

Run from the root directory with:
    pytest -v
"""

import base64
import pytest
from app.crypto import (
    generate_salt,
    generate_nonce,
    generate_master_key,
    derive_key_argon2id,
    encrypt_xchacha20_poly1305,
    decrypt_xchacha20_poly1305,
    wrap_master_key,
    unwrap_master_key,
    hash_keypad_pin,
    verify_keypad_pin,
)
from nacl.exceptions import CryptoError

class TestKeyGeneration:

    def test_generate_salt_returns_bytes(self):
        """Generate salt should be 16 bytes long and return bytes."""
        salt = generate_salt()
        assert isinstance(salt, bytes)
        assert len(salt) == 16

    def test_generate_nonce_returns_bytes(self):
        """Generate nonce should be 24 bytes long and return bytes."""
        nonce = generate_nonce()
        assert isinstance(nonce, bytes)
        assert len(nonce) == 24

    def test_generate_master_key_returns_bytes(self):
        """Generate master key should be 32 bytes long and return bytes."""
        master_key = generate_master_key()
        assert isinstance(master_key, bytes)
        assert len(master_key) == 32

    def test_generate_salt_unique(self):
        """Generate salt should be unique."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        assert salt1 != salt2


class TestArgon2Derivation:

    def test_derive_key_returns_correct_length(self):
        """Derive key should be 32 bytes long and return bytes."""
        salt = generate_salt() # Must be 16 bytes
        derived_key = derive_key_argon2id("test", salt)
        assert isinstance(derived_key, bytes)
        assert len(derived_key) == 32

    def test_derive_key_deterministic(self):
        """Derive key should be deterministic."""
        salt = generate_salt()
        key1 = derive_key_argon2id("test", salt)
        key2 = derive_key_argon2id("test", salt)
        assert key1 == key2

    def test_derive_key_different_salt(self):
        """Derive key should be different with different salt."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        key1 = derive_key_argon2id("test", salt1)
        key2 = derive_key_argon2id("test", salt2)
        assert key1 != key2

    def test_derive_key_different_passphrase(self):
        """Derive key should be different with different passphrase."""
        salt = generate_salt()
        key1 = derive_key_argon2id("test", salt)
        key2 = derive_key_argon2id("test2", salt)
        assert key1 != key2

    def test_derive_key_different_params(self):
        """Derive key should be different with different parameters."""
        salt = generate_salt()
        key1 = derive_key_argon2id("test", salt)
        key2 = derive_key_argon2id("test", salt, memory_cost=32768)
        assert key1 != key2

    def test_derive_key_different_key_length(self):
        """Derive key should be different with different key length."""
        salt = generate_salt()
        key1 = derive_key_argon2id("test", salt)
        key2 = derive_key_argon2id("test", salt, key_length=16)
        assert key1 != key2


class TestEncryptDecrypt:

    def test_roundtrip(self):
        """Test that encryption and decryption work correctly."""
        plaintext = b"test data"
        key = generate_master_key()
        ciphertext_b64, nonce_b64 = encrypt_xchacha20_poly1305(plaintext, key)
        decrypted = decrypt_xchacha20_poly1305(ciphertext_b64, nonce_b64, key)
        assert decrypted == plaintext

    def test_wrong_key_fails(self):
        """Decryption with wrong key should raise CryptoError."""
        plaintext = b"test data"
        key1 = generate_master_key()
        key2 = generate_master_key()
        ciphertext_b64, nonce_b64 = encrypt_xchacha20_poly1305(plaintext, key1)
        
        # We EXPECT this to raise an error
        with pytest.raises(CryptoError):
            decrypt_xchacha20_poly1305(ciphertext_b64, nonce_b64, key2)

    def test_tampered_ciphertext_fails(self):
        """Changed ciphertext should fail authentication."""
        plaintext = b"test data"
        key = generate_master_key()
        ciphertext_b64, nonce_b64 = encrypt_xchacha20_poly1305(plaintext, key)
        
        ciphertext_bytes = bytearray(base64.b64decode(ciphertext_b64))
        ciphertext_bytes[0] ^= 0x01 # Flip just one bit
        tampered_b64 = base64.b64encode(ciphertext_bytes).decode("utf-8")
        
        with pytest.raises(CryptoError):
            decrypt_xchacha20_poly1305(tampered_b64, nonce_b64, key)


class TestMasterKeyWrapping:

    def test_wrap_unwrap_roundtrip(self):
        """Wrap then unwrap should return original master key."""
        master_key = generate_master_key()
        wrapping_key = generate_master_key()
        wrapped_b64, nonce_b64 = wrap_master_key(master_key, wrapping_key)
        unwrapped = unwrap_master_key(wrapped_b64, nonce_b64, wrapping_key)
        assert unwrapped == master_key

    def test_wrong_wrapping_key_fails(self):
        """Unwrap with wrong key should raise CryptoError."""
        master_key = generate_master_key()
        wrapping_key1 = generate_master_key()
        wrapping_key2 = generate_master_key()
        wrapped_b64, nonce_b64 = wrap_master_key(master_key, wrapping_key1)
        
        with pytest.raises(CryptoError):
            unwrap_master_key(wrapped_b64, nonce_b64, wrapping_key2)


class TestPinHashing:

    def test_hash_and_verify(self):
        """Correct PIN should verify."""
        pin = "1234"
        salt = generate_salt()
        hashed_pin = hash_keypad_pin(pin, salt)
        assert verify_keypad_pin(pin, hashed_pin, salt)

    def test_wrong_pin_fails(self):
        """Wrong PIN should not verify."""
        pin = "1234"
        salt = generate_salt()
        hashed_pin = hash_keypad_pin(pin, salt)
        assert not verify_keypad_pin("5678", hashed_pin, salt)
