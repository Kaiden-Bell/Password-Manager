"""
crypto.py — Core cryptographic operations.

Uses argon2-cffi for key derivation and PyNaCl for symmetric encryption.
"""

import base64
import hashlib
import os

from argon2.low_level import hash_secret_raw, Type
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from nacl.exceptions import CryptoError

from app.config import (
    ARGON2_MEMORY_COST,
    ARGON2_TIME_COST,
    ARGON2_PARALLELISM,
    KEY_LENGTH,
)

# --------------------------------
# Random generation              |
# (salt, nonce, and master key)  |
# --------------------------------

def generate_salt() -> bytes:
    """
        Desc: Generate a cryptographically secure random salt (16 bytes).
        Arguments: None
        Returns: bytes
    """

    salt = os.urandom(16)

    return salt

def generate_nonce() -> bytes:
    """
        Desc: Generate a cryptographically secure random nonce (24 bytes).
        Arguments: None
        Returns: bytes
    """

    nonce = os.urandom(24)

    return nonce

def generate_master_key() -> bytes:
    """
        Desc: Generate a cryptographically secure random master key (32 bytes).
        Arguments: None
        Returns: bytes
    """

    master_key = os.urandom(KEY_LENGTH)

    return master_key

# -------------------
# Key derivation    |
# (Argon2id-based)  |
# -------------------

def derive_key_argon2id(
    secret: str | bytes,
    salt: bytes,
    memory_cost: int = ARGON2_MEMORY_COST,
    time_cost: int = ARGON2_TIME_COST,
    parallelism: int = ARGON2_PARALLELISM,
    key_length: int = KEY_LENGTH,
) -> bytes:
    """
        Desc: Derive a cryptographic key using Argon2id.
        Arguments: secret, salt, memory_cost, time_cost, parallelism, key_length
        Returns: bytes
    """

    if isinstance(secret, str):
        secret = secret.encode("utf-8")

    derived_key = hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=key_length,
        type=Type.ID,
    )

    return derived_key

# --------------------
# Encryption         |
# XChaCha20-Poly1305 |
# --------------------

def encrypt_xchacha20_poly1305(
    plaintext_bytes: bytes,
    key: bytes,
) -> tuple[str, str]:
    """
        Desc: Encrypt data using XChaCha20-Poly1305 (AEAD).
        Arguments: plaintext_bytes, key
        Returns: tuple[str, str], base64 ciphertext and base64 nonce
    """

    box = SecretBox(key)
    nonce = nacl_random(box.NONCE_SIZE)
    encrypted = box.encrypt(plaintext_bytes, nonce)

    ciphertext_only = encrypted.ciphertext

    return base64.b64encode(ciphertext_only).decode("utf-8"), base64.b64encode(nonce).decode("utf-8")


def decrypt_xchacha20_poly1305(
    ciphertext_b64: str,
    nonce_b64: str,
    key: bytes,
) -> bytes:
    """
        Desc: Decrypt data using XChaCha20-Poly1305 (AEAD).
        Arguments: ciphertext_b64, nonce_b64, key
        Returns: bytes, decrypted plaintext
    """

    box = SecretBox(key)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)

    decrypted = box.decrypt(ciphertext, nonce)

    return decrypted

# ------------------------
# Master key wrapping    |
# (XChaCha20-Poly1305)   |
# ------------------------

def wrap_master_key(
    master_key: bytes,
    wrapping_key: bytes,
) -> tuple[str, str]:
    """
        Desc: Wrap (encrypt) the master key using a wrapping key.
        Arguments: master_key, wrapping_key
        Returns: tuple[str, str], base64 wrapped key and base64 nonce
    """

    return encrypt_xchacha20_poly1305(master_key, wrapping_key)

def unwrap_master_key(
    wrapped_master_key_b64: str,
    nonce_b64: str,
    wrapping_key: bytes,
) -> bytes:
    """
        Desc: Unwrap (decrypt) the master key using a wrapping key.
        Arguments: wrapped_master_key_b64, nonce_b64, wrapping_key
        Returns: bytes, unwrapped master key
    """

    try:
        return decrypt_xchacha20_poly1305(wrapped_master_key_b64, nonce_b64, wrapping_key)
    except CryptoError:
        raise

# --------------------
# Keypad PIN         |
# (Hardware Hashing) |
# --------------------

def hash_keypad_pin(pin: str, salt: bytes) -> str:
    """
        Desc: Hash a hardware keypad PIN using SHA-256 and a salt.
        Arguments: pin, salt
        Returns: str, hex-encoded hash
    """

    return hashlib.sha256(salt + pin.encode()).hexdigest()

def verify_keypad_pin(
    pin_attempt: str,
    stored_hash: str,
    salt: bytes,
) -> bool:
    """
        Desc: Verify a keypad PIN attempt against a stored hash.
        Arguments: pin_attempt, stored_hash, salt
        Returns: bool, True if correct, False otherwise
    """

    return hash_keypad_pin(pin_attempt, salt) == stored_hash
