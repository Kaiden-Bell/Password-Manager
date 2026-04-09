"""
app.crypto
──────────
Cryptographic primitives for The Vault.

- Key derivation  : PBKDF2-HMAC-SHA256
- Key wrapping    : AES-256-GCM (wrapping key encrypts master key)
- Vault encryption: AES-256-GCM (master key encrypts vault payload)
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Constants ─────────────────────────────────────

KEY_LENGTH = 32          # 256-bit keys
SALT_LENGTH = 32         # 256-bit salts
NONCE_LENGTH = 12        # 96-bit nonces (AES-GCM standard)
DEFAULT_KDF_ITERATIONS = 600_000


# ── Key Derivation ────────────────────────────────

def derive_key(
    secret: str | bytes,
    salt: bytes,
    iterations: int = DEFAULT_KDF_ITERATIONS,
) -> bytes:
    """
    Derive a 256-bit wrapping key from a secret (PIN or passphrase)
    using PBKDF2-HMAC-SHA256.
    """
    if isinstance(secret, str):
        secret = secret.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(secret)


# ── Master Key Management ─────────────────────────

def generate_master_key() -> bytes:
    """Generate a cryptographically random 256-bit vault master key."""
    return os.urandom(KEY_LENGTH)


def generate_salt() -> bytes:
    """Generate a cryptographically random salt."""
    return os.urandom(SALT_LENGTH)


# ── Key Wrapping (AES-GCM) ───────────────────────

def wrap_key(master_key: bytes, wrapping_key: bytes) -> bytes:
    """
    Encrypt (wrap) the vault master key with a wrapping key
    derived from the user's PIN or passphrase.

    Returns a blob:  nonce (12 B) || ciphertext+tag
    """
    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(wrapping_key)
    ct = aesgcm.encrypt(nonce, master_key, associated_data=None)
    return nonce + ct


def unwrap_key(wrapped_blob: bytes, wrapping_key: bytes) -> bytes:
    """
    Decrypt (unwrap) the vault master key.

    Raises ``cryptography.exceptions.InvalidTag`` if the wrapping key
    is wrong (i.e. wrong PIN or passphrase).
    """
    nonce = wrapped_blob[:NONCE_LENGTH]
    ct = wrapped_blob[NONCE_LENGTH:]
    aesgcm = AESGCM(wrapping_key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)


# ── Vault Payload Encryption ─────────────────────

def encrypt_vault(data: bytes, master_key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt raw vault data with the master key (AES-256-GCM).

    Returns ``(nonce, ciphertext_with_tag)``.
    """
    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(master_key)
    ct = aesgcm.encrypt(nonce, data, associated_data=None)
    return nonce, ct


def decrypt_vault(ciphertext: bytes, nonce: bytes, master_key: bytes) -> bytes:
    """
    Decrypt vault data previously encrypted with ``encrypt_vault``.

    Raises ``cryptography.exceptions.InvalidTag`` on tamper / wrong key.
    """
    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
