"""
app.vault
─────────
High-level vault file operations.

Each user gets a separate vault file stored as JSON under the configured
vault directory.  The file format is::

    {
        "nonce": "<base64>",
        "ciphertext": "<base64>"
    }

The *ciphertext* is AES-256-GCM encrypted JSON containing the user's
stored credentials::

    {
        "credentials": [
            {
                "service": "GitHub",
                "username": "kbell",
                "password": "hunter2",
                "created_at": "2026-04-08T22:00:00Z"
            },
            ...
        ]
    }
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from app.crypto import decrypt_vault, encrypt_vault


# ── Vault CRUD ────────────────────────────────────

def create_vault(vault_dir: str, vault_filename: str, master_key: bytes) -> str:
    """
    Create a new, empty vault file.

    Returns the absolute path of the created vault file.
    """
    vault_path = _resolve_path(vault_dir, vault_filename)
    empty_payload = json.dumps({"credentials": []}).encode("utf-8")
    _write_encrypted(vault_path, empty_payload, master_key)
    return str(vault_path)


def read_vault(vault_dir: str, vault_filename: str, master_key: bytes) -> dict:
    """
    Decrypt and return the vault contents as a Python dict.

    Raises ``FileNotFoundError`` if the vault file is missing.
    """
    vault_path = _resolve_path(vault_dir, vault_filename)
    plaintext = _read_encrypted(vault_path, master_key)
    return json.loads(plaintext)


def write_vault(
    vault_dir: str,
    vault_filename: str,
    master_key: bytes,
    data: dict,
) -> None:
    """Re-encrypt and overwrite the vault file with new data."""
    vault_path = _resolve_path(vault_dir, vault_filename)
    payload = json.dumps(data, indent=2).encode("utf-8")
    _write_encrypted(vault_path, payload, master_key)


def add_credential(
    vault_dir: str,
    vault_filename: str,
    master_key: bytes,
    service: str,
    username: str,
    password: str,
) -> dict:
    """
    Append a credential to the vault and return the updated vault dict.
    """
    data = read_vault(vault_dir, vault_filename, master_key)

    credential = {
        "service": service,
        "username": username,
        "password": password,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    data.setdefault("credentials", []).append(credential)

    write_vault(vault_dir, vault_filename, master_key, data)
    return data


# ── Internal helpers ──────────────────────────────

def _resolve_path(vault_dir: str, filename: str) -> Path:
    """Ensure the vault directory exists and return the full path."""
    path = Path(vault_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path / filename


def _write_encrypted(path: Path, plaintext: bytes, master_key: bytes) -> None:
    """Encrypt plaintext and write the JSON envelope to disk."""
    nonce, ciphertext = encrypt_vault(plaintext, master_key)
    envelope = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")


def _read_encrypted(path: Path, master_key: bytes) -> bytes:
    """Read the JSON envelope from disk and decrypt."""
    if not path.exists():
        raise FileNotFoundError(f"Vault file not found: {path}")

    envelope = json.loads(path.read_text(encoding="utf-8"))
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    return decrypt_vault(ciphertext, nonce, master_key)
