"""
database.py — Lightweight SQLite helper layer.

Uses Python's built-in sqlite3 module. All functions operate on the database
file specified by config.DATABASE_PATH.
"""

import os
import sqlite3
from datetime import datetime, timezone

from app.config import DATABASE_PATH


# --------
# Schema |
# --------

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
    created_at TEXT NOT NULL,
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
    created_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
"""


# ------------
# Connection |
# ------------

def get_connection() -> sqlite3.Connection:
    """
        Desc: Establish a connection to the SQLite database.
        Arguments: None
        Returns: sqlite3.Connection
    """

    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database() -> None:
    """
        Desc: Create all database tables if they do not already exist.
        Arguments: None
        Returns: None
    """


    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = get_connection()
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()

def _now() -> str:
    """
        Desc: Get the current UTC time in ISO 8601 format.
        Arguments: None
        Returns: str
    """


    return datetime.now(timezone.utc).isoformat()

# -----------
# User CRUD |
# -----------

def create_user(username: str, display_name: str) -> int:
    """
        Desc: Create a new user record in the database.
        Arguments: username, display_name
        Returns: int, the new user's ID
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, display_name, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, display_name, _now(), _now()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def get_user_by_username(username: str) -> dict | None:
    """
        Desc: Retrieve a user record by their username.
        Arguments: username
        Returns: dict or None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


# ------------
# Vault CRUD |
# ------------

def get_all_vaults() -> list[dict]:
    """
        Desc: Return all vaults in the database.
        Arguments: None
        Returns: list[dict]
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT vault_id, vault_name FROM vaults ORDER BY vault_id")
        return [{"vault_id": row["vault_id"], "vault_name": row["vault_name"]} for row in cursor.fetchall()]
    finally:
        conn.close()

def get_user_vaults(username: str) -> list[dict]:
    """
        Desc: Return all vaults (id + name) for a specific user.
        Arguments: username
        Returns: list[dict]
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT v.vault_id, v.vault_name 
            FROM vaults v
            JOIN users u ON v.user_id = u.user_id
            WHERE u.username = ?
            ORDER BY v.vault_id
            """, (username,)
        )
        return [{"vault_id": row["vault_id"], "vault_name": row["vault_name"]} for row in cursor.fetchall()]
    finally:
        conn.close()

def create_vault(user_id: int, vault_name: str) -> int:
    """
        Desc: Create a new vault record associated with a user.
        Arguments: user_id, vault_name
        Returns: int, the new vault's ID
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO vaults (user_id, vault_name, vault_status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, vault_name, "LOCKED", _now(), _now()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def delete_vault(vault_id: int) -> None:
    """
        Desc: Delete a vault and ALL associated data (policy, auth, hardware, encrypted data, logs).
        Arguments: vault_id
        Returns: None
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT user_id FROM vaults WHERE vault_id = ?", (vault_id,))
        row = cursor.fetchone()
        if row is None:
            raise ValueError(f"Vault {vault_id} does not exist.")
        user_id = row["user_id"]

        cursor.execute("DELETE FROM access_logs     WHERE vault_id = ?", (vault_id,))
        cursor.execute("DELETE FROM vault_data       WHERE vault_id = ?", (vault_id,))
        cursor.execute("DELETE FROM hardware_devices WHERE vault_id = ?", (vault_id,))
        cursor.execute("DELETE FROM hardware_auth    WHERE vault_id = ?", (vault_id,))
        cursor.execute("DELETE FROM auth_credentials WHERE vault_id = ?", (vault_id,))
        cursor.execute("DELETE FROM vault_policy     WHERE vault_id = ?", (vault_id,))
        cursor.execute("DELETE FROM vaults           WHERE vault_id = ?", (vault_id,))

        cursor.execute("SELECT COUNT(*) as cnt FROM vaults WHERE user_id = ?", (user_id,))
        if cursor.fetchone()["cnt"] == 0:
            cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

        conn.commit()
    finally:
        conn.close()



def load_vault(vault_id: int) -> dict | None:
    """
        Desc: Load basic metadata for a specific vault.
        Arguments: vault_id
        Returns: dict or None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * 
            FROM vaults 
            WHERE vault_id = ?
            """,
            (vault_id,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def create_vault_policy(
    vault_id: int,
    hardware_gate_required: bool = False,
    software_only_enabled: bool = True,
    gate_window_seconds: int = 60,
) -> int:
    """
        Desc: Create a security policy for a vault.
        Arguments: vault_id, hardware_gate_required, software_only_enabled, gate_window_seconds
        Returns: int, the new policy's ID
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO vault_policy (vault_id, hardware_gate_required, software_only_enabled, gate_window_seconds, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (vault_id, hardware_gate_required, software_only_enabled, gate_window_seconds, _now(), _now()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

# ------------
# Auth Creds |
# ------------

def save_auth_credentials(
    vault_id: int,
    passphrase_salt: str,
    wrapped_master_key: str,
    wrapped_master_key_nonce: str,
    kdf_params: dict,
) -> int:
    """
        Desc: Save passphrase-based authentication credentials.
        Arguments: vault_id, passphrase_salt, wrapped_master_key, wrapped_master_key_nonce, kdf_params
        Returns: int, the new record's ID
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO auth_credentials (vault_id, passphrase_salt, wrapped_master_key, wrapped_master_key_nonce, kdf_name, kdf_memory_cost, kdf_time_cost, kdf_parallelism, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (vault_id, passphrase_salt, wrapped_master_key, wrapped_master_key_nonce, kdf_params.get("kdf_name", "argon2id"), kdf_params.get("memory_cost", kdf_params.get("kdf_memory_cost")), kdf_params.get("time_cost", kdf_params.get("kdf_time_cost")), kdf_params.get("parallelism", kdf_params.get("kdf_parallelism")), _now(), _now()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def load_auth_credentials(vault_id: int) -> dict | None:
    """
        Desc: Load authentication credentials for a vault.
        Arguments: vault_id
        Returns: dict or None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * 
            FROM auth_credentials 
            WHERE vault_id = ?
            """,
            (vault_id,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

# ----------
# Hardware |
# ----------

def save_hardware_auth(
    vault_id: int,
    keypad_pin_hash: str,
    keypad_pin_salt: str,
) -> int:
    """
        Desc: Save hardware-based authentication (PIN) data.
        Arguments: vault_id, keypad_pin_hash, keypad_pin_salt
        Returns: int, the new record's ID
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO hardware_auth (vault_id, keypad_pin_hash, keypad_pin_salt, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (vault_id, keypad_pin_hash, keypad_pin_salt, _now(), _now()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def load_hardware_auth(vault_id: int) -> dict | None:
    """
        Desc: Load hardware authentication data for a vault.
        Arguments: vault_id
        Returns: dict or None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * 
            FROM hardware_auth 
            WHERE vault_id = ?
            """,
            (vault_id,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def increment_failed_pin_attempts(vault_id: int) -> None:
    """
        Desc: Increment the count of failed PIN attempts for a vault.
        Arguments: vault_id
        Returns: None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE hardware_auth 
            SET failed_attempts = failed_attempts + 1, updated_at = ?
            WHERE vault_id = ?
            """,
            (_now(), vault_id),
        )
        conn.commit()
    finally:
        conn.close()

def get_failed_pin_attempts(vault_id: int) -> int:
    """
        Desc: Get the number of failed PIN attempts for a vault.
        Arguments: vault_id
        Returns: int
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT failed_attempts 
            FROM hardware_auth 
            WHERE vault_id = ?
            """, (vault_id,))
        row = cursor.fetchone()
        return row["failed_attempts"] if row else 0
    finally:
        conn.close()

def reset_failed_pin_attempts(vault_id: int) -> None:
    """
        Desc: Reset the failed PIN attempts counter to zero.
        Arguments: vault_id
        Returns: None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE hardware_auth 
            SET failed_attempts = 0, last_success_at = ? 
            WHERE vault_id = ?
            """,
            (_now(), vault_id),
        )
        conn.commit()
    finally:
        conn.close()

# ---------------
# Vault Status  |
# ---------------

def lock_vault(vault_id: int) -> None:
    """
        Desc: Set a vault's status to 'LOCKED'.
        Arguments: vault_id
        Returns: None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE vaults 
            SET vault_status = 'LOCKED', updated_at = ?
            WHERE vault_id = ?
            """,
            (_now(), vault_id),
        )
        conn.commit()
    finally:
        conn.close()

def unlock_vault(vault_id: int) -> None:
    """
        Desc: Set a vault's status to 'UNLOCKED'.
        Arguments: vault_id
        Returns: None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE vaults 
            SET vault_status = 'UNLOCKED', updated_at = ?
            WHERE vault_id = ?
            """,
            (_now(), vault_id),
        )
        conn.commit()
    finally:
        conn.close()

# --------------
# Vault Policy |
# --------------

def load_vault_policy(vault_id: int) -> dict | None:
    """
        Desc: Load the security policy for a vault.
        Arguments: vault_id
        Returns: dict or None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * 
            FROM vault_policy 
            WHERE vault_id = ?
            """,
            (vault_id,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

# ----------------------
# Vault Data Encrypted |
# ----------------------

def save_vault_data(
    vault_id: int,
    encrypted_blob: str,
    nonce: str,
    algorithm: str = "xchacha20-poly1305",
) -> int:
    """
        Desc: Save the encrypted vault data blob.
        Arguments: vault_id, encrypted_blob, nonce, algorithm
        Returns: int, the new record's ID
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO vault_data (vault_id, encrypted_blob, nonce, algorithm, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (vault_id, encrypted_blob, nonce, algorithm, _now(), _now()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def load_vault_data(vault_id: int) -> dict | None:
    """
        Desc: Load the encrypted vault data blob for a vault.
        Arguments: vault_id
        Returns: dict or None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * 
            FROM vault_data 
            WHERE vault_id = ?
            """,
            (vault_id,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def update_vault_data(
    vault_id: int,
    encrypted_blob: str,
    nonce: str,
) -> None:
    """
        Desc: Update the encrypted vault data blob for an existing vault.
        Arguments: vault_id, encrypted_blob, nonce
        Returns: None
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE vault_data 
            SET encrypted_blob = ?, nonce = ?, algorithm = ?, updated_at = ? 
            WHERE vault_id = ?
            """,
            (encrypted_blob, nonce, "xchacha20-poly1305", _now(), vault_id),
        )
        conn.commit()
    finally:
        conn.close()

# -------------
# Access Logs |
# -------------

def write_access_log(
    vault_id: int | None,
    user_id: int | None,
    event_type: str,
    auth_method: str | None,
    success: bool,
    details: str | None = None,
) -> int:
    """
        Desc: Record an access attempt or security event in the logs.
        Arguments: vault_id, user_id, event_type, auth_method, success, details
        Returns: int, the new log record's ID
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO access_logs (vault_id, user_id, event_type, auth_method, success, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (vault_id, user_id, event_type, auth_method, success, details, _now()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def get_access_logs(vault_id: int | None = None, user_id: int | None = None) -> list[dict]:
    """
        Desc: Retrieve access logs, optionally filtered by vault or user.
        Arguments: vault_id, user_id
        Returns: list[dict]
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        query = "SELECT log_id, vault_id, user_id, event_type, auth_method, success, details, created_at as timestamp FROM access_logs"
        params = []
        conditions = []
        
        if vault_id is not None:
            conditions.append("vault_id = ?")
            params.append(vault_id)
        if user_id is not None:
            conditions.append("user_id = ?")
            params.append(user_id)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY created_at DESC"
        
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        
        return [dict(row) for row in rows]
    finally:
        conn.close()
