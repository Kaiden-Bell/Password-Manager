"""
database.py — Lightweight SQLite helper layer.

Uses Python's built-in sqlite3 module. All functions operate on the database
file specified by config.DATABASE_PATH.
"""

import os
import sqlite3
from datetime import datetime, timezone

from app.config import DATABASE_PATH


# ═══════════════════════════════════════════════════════════════════════════
# Schema DDL
# ═══════════════════════════════════════════════════════════════════════════

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vaults (
    vault_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    vault_name TEXT NOT NULL,
    vault_status TEXT NOT NULL DEFAULT 'LOCKED',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS vault_policy (
    policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER UNIQUE NOT NULL,
    hardware_gate_required INTEGER NOT NULL DEFAULT 0,
    software_only_enabled INTEGER NOT NULL DEFAULT 1,
    gate_window_seconds INTEGER NOT NULL DEFAULT 60,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE IF NOT EXISTS auth_credentials (
    auth_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER UNIQUE NOT NULL,
    passphrase_salt TEXT NOT NULL,
    wrapped_master_key TEXT NOT NULL,
    wrapped_master_key_nonce TEXT NOT NULL,
    kdf_name TEXT NOT NULL DEFAULT 'argon2id',
    kdf_memory_cost INTEGER NOT NULL,
    kdf_time_cost INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE IF NOT EXISTS hardware_auth (
    hardware_auth_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER UNIQUE NOT NULL,
    keypad_pin_hash TEXT NOT NULL,
    keypad_pin_salt TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_success_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE IF NOT EXISTS hardware_devices (
    device_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    serial_port TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE IF NOT EXISTS vault_data (
    data_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER UNIQUE NOT NULL,
    encrypted_blob TEXT NOT NULL,
    nonce TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'xchacha20-poly1305',
    updated_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE IF NOT EXISTS access_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    auth_method TEXT,
    success INTEGER NOT NULL,
    details TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
"""


# ═══════════════════════════════════════════════════════════════════════════
# Connection Helper
# ═══════════════════════════════════════════════════════════════════════════

def get_connection() -> sqlite3.Connection:
    """Return a new SQLite connection with row-factory enabled."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database() -> None:
    """Create all tables if they do not already exist."""
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = get_connection()
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# Timestamp Helper
# ═══════════════════════════════════════════════════════════════════════════

def _now() -> str:
    """Return current UTC timestamp as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════════
# User CRUD
# ═══════════════════════════════════════════════════════════════════════════

def create_user(username: str, display_name: str) -> int:
    """
    Insert a new user and return their user_id.

    TODO: Implement INSERT into users table.
    """
    raise NotImplementedError("create_user")


# ═══════════════════════════════════════════════════════════════════════════
# Vault CRUD
# ═══════════════════════════════════════════════════════════════════════════

def create_vault(user_id: int, vault_name: str) -> int:
    """
    Insert a new vault for a user and return the vault_id.

    TODO: Implement INSERT into vaults table.
    """
    raise NotImplementedError("create_vault")


def create_vault_policy(
    vault_id: int,
    hardware_gate_required: bool = False,
    software_only_enabled: bool = True,
    gate_window_seconds: int = 60,
) -> int:
    """
    Insert a vault policy row and return the policy_id.

    TODO: Implement INSERT into vault_policy table.
    """
    raise NotImplementedError("create_vault_policy")


# ═══════════════════════════════════════════════════════════════════════════
# Auth Credentials
# ═══════════════════════════════════════════════════════════════════════════

def save_auth_credentials(
    vault_id: int,
    passphrase_salt: str,
    wrapped_master_key: str,
    wrapped_master_key_nonce: str,
    kdf_params: dict,
) -> int:
    """
    Store the passphrase-derived auth credentials for a vault.

    kdf_params should contain:
        kdf_memory_cost, kdf_time_cost, kdf_parallelism

    TODO: Implement INSERT into auth_credentials table.
    """
    raise NotImplementedError("save_auth_credentials")


def load_auth_credentials(vault_id: int) -> dict | None:
    """
    Load auth credentials for a vault.

    Returns a dict with keys matching the auth_credentials columns,
    or None if not found.

    TODO: Implement SELECT from auth_credentials.
    """
    raise NotImplementedError("load_auth_credentials")


# ═══════════════════════════════════════════════════════════════════════════
# Hardware Auth
# ═══════════════════════════════════════════════════════════════════════════

def save_hardware_auth(
    vault_id: int,
    keypad_pin_hash: str,
    keypad_pin_salt: str,
) -> int:
    """
    Store the hashed keypad PIN for a vault.

    TODO: Implement INSERT into hardware_auth table.
    """
    raise NotImplementedError("save_hardware_auth")


def load_hardware_auth(vault_id: int) -> dict | None:
    """
    Load hardware auth record for a vault.

    Returns a dict or None if not found.

    TODO: Implement SELECT from hardware_auth.
    """
    raise NotImplementedError("load_hardware_auth")


def increment_failed_pin_attempts(vault_id: int) -> None:
    """
    Increment the failed_attempts counter in hardware_auth.

    TODO: Implement UPDATE on hardware_auth.
    """
    raise NotImplementedError("increment_failed_pin_attempts")


def reset_failed_pin_attempts(vault_id: int) -> None:
    """
    Reset the failed_attempts counter to 0 and update last_success_at.

    TODO: Implement UPDATE on hardware_auth.
    """
    raise NotImplementedError("reset_failed_pin_attempts")


# ═══════════════════════════════════════════════════════════════════════════
# Vault Policy
# ═══════════════════════════════════════════════════════════════════════════

def load_vault_policy(vault_id: int) -> dict | None:
    """
    Load the vault policy for a vault.

    Returns a dict or None if not found.

    TODO: Implement SELECT from vault_policy.
    """
    raise NotImplementedError("load_vault_policy")


# ═══════════════════════════════════════════════════════════════════════════
# Vault Data (Encrypted Blob)
# ═══════════════════════════════════════════════════════════════════════════

def save_vault_data(
    vault_id: int,
    encrypted_blob: str,
    nonce: str,
    algorithm: str = "xchacha20-poly1305",
) -> int:
    """
    Store the encrypted vault blob.

    TODO: Implement INSERT into vault_data table.
    """
    raise NotImplementedError("save_vault_data")


def load_vault_data(vault_id: int) -> dict | None:
    """
    Load the encrypted vault blob for a vault.

    Returns a dict or None if not found.

    TODO: Implement SELECT from vault_data.
    """
    raise NotImplementedError("load_vault_data")


def update_vault_data(
    vault_id: int,
    encrypted_blob: str,
    nonce: str,
) -> None:
    """
    Update the encrypted vault blob after a credential mutation.

    TODO: Implement UPDATE on vault_data.
    """
    raise NotImplementedError("update_vault_data")


# ═══════════════════════════════════════════════════════════════════════════
# Access Logs
# ═══════════════════════════════════════════════════════════════════════════

def write_access_log(
    vault_id: int | None,
    user_id: int | None,
    event_type: str,
    auth_method: str | None,
    success: bool,
    details: str | None = None,
) -> int:
    """
    Write an entry to the access_logs table.

    TODO: Implement INSERT into access_logs.
    """
    raise NotImplementedError("write_access_log")
