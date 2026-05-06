"""
database.py — Lightweight PostgreSQL helper layer.

Uses psycopg2. All functions operate on the database
specified by config.DATABASE_URL.
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone

from app.config import DATABASE_URL

SCHEMA_SQL = """

CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vaults (
    vault_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    vault_name TEXT NOT NULL,
    vault_status TEXT NOT NULL DEFAULT 'LOCKED',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    UNIQUE(user_id, vault_name)
);

CREATE TABLE IF NOT EXISTS vault_policy (
    policy_id SERIAL PRIMARY KEY,
    vault_id INTEGER UNIQUE NOT NULL,
    hardware_gate_required INTEGER NOT NULL DEFAULT 0,
    software_only_enabled INTEGER NOT NULL DEFAULT 1,
    gate_window_seconds INTEGER NOT NULL DEFAULT 60,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE IF NOT EXISTS auth_credentials (
    auth_id SERIAL PRIMARY KEY,
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
    hardware_auth_id SERIAL PRIMARY KEY,
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
    device_id SERIAL PRIMARY KEY,
    vault_id INTEGER NOT NULL,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    serial_port TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id),
    UNIQUE(vault_id, device_name)
);

CREATE TABLE IF NOT EXISTS vault_data (
    data_id SERIAL PRIMARY KEY,
    vault_id INTEGER UNIQUE NOT NULL,
    encrypted_blob TEXT NOT NULL,
    nonce TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'xchacha20-poly1305',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE IF NOT EXISTS access_logs (
    log_id SERIAL PRIMARY KEY,
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

class VaultDatabase:
    def __init__(self, db_url: str):
        self.db_url = db_url

    def get_connection(self):
        conn = psycopg2.connect(self.db_url, cursor_factory=RealDictCursor)
        return conn

    def initialize_database(self) -> None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_user(self, username: str) -> int:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    INSERT INTO users (username, display_name, created_at, updated_at) 
                    VALUES (%s, %s, %s, %s) 
                    RETURNING user_id
                """,
                (username, username, self._now(), self._now()),
            )
            conn.commit()
            return cursor.fetchone()['user_id']
        finally:
            conn.close()

    def get_user_by_username(self, username: str) -> dict | None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    SELECT * 
                    FROM users 
                    WHERE username = %s
                """,
                (username,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def get_all_vaults(self) -> list[dict]:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    SELECT vault_id, vault_name 
                    FROM vaults 
                    ORDER BY vault_id
                """
            )
            return [{"vault_id": row["vault_id"], "vault_name": row["vault_name"]} for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_user_vaults(self, username: str) -> list[dict]:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    SELECT v.vault_id, v.vault_name 
                    FROM vaults v 
                    JOIN users u ON v.user_id = u.user_id 
                    WHERE u.username = %s 
                    ORDER BY v.vault_id
                """, 
                (username,)
            )
            return [{"vault_id": row["vault_id"], "vault_name": row["vault_name"]} for row in cursor.fetchall()]
        finally:
            conn.close()

    def create_vault(self, user_id: int, vault_name: str) -> int:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    INSERT INTO vaults (
                        user_id, 
                        vault_name, 
                        vault_status, 
                        created_at, 
                        updated_at
                    ) 
                    VALUES (%s, %s, %s, %s, %s) 
                    RETURNING vault_id
                """,
                (user_id, vault_name, "LOCKED", self._now(), self._now()),
            )
            conn.commit()
            return cursor.fetchone()['vault_id']
        finally:
            conn.close()

    def delete_vault(self, vault_id: int) -> None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute(
                """
                    SELECT user_id 
                    FROM vaults 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError(f"Vault {vault_id} does not exist.")
            user_id = row["user_id"]

            cursor.execute(
                """
                    DELETE FROM access_logs 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            cursor.execute(
                """
                    DELETE FROM vault_data 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            cursor.execute(
                """
                    DELETE FROM hardware_devices 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            cursor.execute(
                """
                    DELETE FROM hardware_auth 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            cursor.execute(
                """
                    DELETE FROM auth_credentials 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            cursor.execute(
                """
                    DELETE FROM vault_policy 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            cursor.execute(
                """
                    DELETE FROM vaults 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )

            cursor.execute(
                """
                    SELECT COUNT(*) as cnt 
                    FROM vaults 
                    WHERE user_id = %s
                """, 
                (user_id,)
            )
            if cursor.fetchone()["cnt"] == 0:
                cursor.execute(
                    """
                        DELETE FROM users 
                        WHERE user_id = %s
                    """, 
                    (user_id,)
                )

            conn.commit()
        finally:
            conn.close()

    def load_vault(self, vault_id: int) -> dict | None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    SELECT * 
                    FROM vaults 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def create_vault_policy(self, vault_id: int, hardware_gate_required: bool = False, software_only_enabled: bool = True, gate_window_seconds: int = 60) -> int:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    INSERT INTO vault_policy (
                        vault_id, 
                        hardware_gate_required, 
                        software_only_enabled, 
                        gate_window_seconds, 
                        created_at, 
                        updated_at
                    ) 
                    VALUES (%s, %s, %s, %s, %s, %s) 
                    RETURNING policy_id
                """,
                (vault_id, int(hardware_gate_required), int(software_only_enabled), gate_window_seconds, self._now(), self._now()),
            )
            conn.commit()
            return cursor.fetchone()['policy_id']
        finally:
            conn.close()

    def save_auth_credentials(self, vault_id: int, passphrase_salt: str, wrapped_master_key: str, wrapped_master_key_nonce: str, kdf_params: dict) -> int:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    INSERT INTO auth_credentials (
                        vault_id, 
                        passphrase_salt, 
                        wrapped_master_key, 
                        wrapped_master_key_nonce, 
                        kdf_name, 
                        kdf_memory_cost, 
                        kdf_time_cost, 
                        kdf_parallelism, 
                        created_at, 
                        updated_at
                    ) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
                    RETURNING auth_id
                """,
                (vault_id, passphrase_salt, wrapped_master_key, wrapped_master_key_nonce, kdf_params.get("kdf_name", "argon2id"), kdf_params.get("memory_cost", kdf_params.get("kdf_memory_cost")), kdf_params.get("time_cost", kdf_params.get("kdf_time_cost")), kdf_params.get("parallelism", kdf_params.get("kdf_parallelism")), self._now(), self._now()),
            )
            conn.commit()
            return cursor.fetchone()['auth_id']
        finally:
            conn.close()

    def load_auth_credentials(self, vault_id: int) -> dict | None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    SELECT * 
                    FROM auth_credentials 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def save_hardware_auth(self, vault_id: int, keypad_pin_hash: str, keypad_pin_salt: str) -> int:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    INSERT INTO hardware_auth (
                        vault_id, 
                        keypad_pin_hash, 
                        keypad_pin_salt, 
                        created_at, 
                        updated_at
                    ) 
                    VALUES (%s, %s, %s, %s, %s) 
                    RETURNING hardware_auth_id
                """,
                (vault_id, keypad_pin_hash, keypad_pin_salt, self._now(), self._now()),
            )
            conn.commit()
            return cursor.fetchone()['hardware_auth_id']
        finally:
            conn.close()

    def load_hardware_auth(self, vault_id: int) -> dict | None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    SELECT * 
                    FROM hardware_auth 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def increment_failed_pin_attempts(self, vault_id: int) -> None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    UPDATE hardware_auth 
                    SET failed_attempts = failed_attempts + 1, updated_at = %s 
                    WHERE vault_id = %s
                """,
                (self._now(), vault_id),
            )
            conn.commit()
        finally:
            conn.close()

    def get_failed_pin_attempts(self, vault_id: int) -> int:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    SELECT failed_attempts 
                    FROM hardware_auth 
                    WHERE vault_id = %s
                """,
                (vault_id,)
            )
            row = cursor.fetchone()
            return row["failed_attempts"] if row else 0
        finally:
            conn.close()

    def reset_failed_pin_attempts(self, vault_id: int) -> None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    UPDATE hardware_auth 
                    SET failed_attempts = 0, last_success_at = %s 
                    WHERE vault_id = %s
                """,
                (self._now(), vault_id),
            )
            conn.commit()
        finally:
            conn.close()

    def lock_vault(self, vault_id: int) -> None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    UPDATE vaults 
                    SET vault_status = 'LOCKED', updated_at = %s 
                    WHERE vault_id = %s
                """,
                (self._now(), vault_id),
            )
            conn.commit()
        finally:
            conn.close()

    def unlock_vault(self, vault_id: int) -> None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    UPDATE vaults 
                    SET vault_status = 'UNLOCKED', updated_at = %s 
                    WHERE vault_id = %s
                """,
                (self._now(), vault_id),
            )
            conn.commit()
        finally:
            conn.close()

    def load_vault_policy(self, vault_id: int) -> dict | None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    SELECT * 
                    FROM vault_policy 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def save_vault_data(self, vault_id: int, encrypted_blob: str, nonce: str, algorithm: str = "xchacha20-poly1305") -> int:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    INSERT INTO vault_data (
                        vault_id, 
                        encrypted_blob, 
                        nonce, 
                        algorithm, 
                        created_at, 
                        updated_at
                    ) 
                    VALUES (%s, %s, %s, %s, %s, %s) 
                    ON CONFLICT (vault_id) DO UPDATE SET 
                        encrypted_blob = EXCLUDED.encrypted_blob, 
                        nonce = EXCLUDED.nonce, 
                        algorithm = EXCLUDED.algorithm, 
                        updated_at = EXCLUDED.updated_at 
                    RETURNING data_id
                """,
                (vault_id, encrypted_blob, nonce, algorithm, self._now(), self._now()),
            )
            conn.commit()
            return cursor.fetchone()['data_id']
        finally:
            conn.close()

    def load_vault_data(self, vault_id: int) -> dict | None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    SELECT * 
                    FROM vault_data 
                    WHERE vault_id = %s
                """, 
                (vault_id,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def update_vault_data(self, vault_id: int, encrypted_blob: str, nonce: str) -> None:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    UPDATE vault_data 
                    SET encrypted_blob = %s, nonce = %s, algorithm = %s, updated_at = %s 
                    WHERE vault_id = %s
                """,
                (encrypted_blob, nonce, "xchacha20-poly1305", self._now(), vault_id),
            )
            conn.commit()
        finally:
            conn.close()

    def write_access_log(self, vault_id: int | None, user_id: int | None, event_type: str, auth_method: str | None, success: bool, details: str | None = None) -> int:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                    INSERT INTO access_logs (vault_id, user_id, event_type, auth_method, success, details, created_at) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s) 
                    RETURNING log_id
                """,
                (vault_id, user_id, event_type, auth_method, int(success), details, self._now()),
            )
            conn.commit()
            return cursor.fetchone()['log_id']
        finally:
            conn.close()

    def get_access_logs(self, vault_id: int | None = None, user_id: int | None = None) -> list[dict]:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            query = "SELECT log_id, vault_id, user_id, event_type, auth_method, success, details, created_at as timestamp FROM access_logs"
            params = []
            conditions = []
            
            if vault_id is not None:
                conditions.append("vault_id = %s")
                params.append(vault_id)
            if user_id is not None:
                conditions.append("user_id = %s")
                params.append(user_id)
                
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
                
            query += " ORDER BY created_at DESC"
            
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            
            return [dict(row) for row in rows]
        finally:
            conn.close()

db = VaultDatabase(DATABASE_URL)
