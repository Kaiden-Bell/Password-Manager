"""
test_database.py — Tests for the database module.

Run with:
    python -m pytest tests/test_database.py -v
"""

import pytest
import sqlite3
import app.database as database

@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch, tmp_path):
    """
    Sets up a temporary SQLite database for each test.
    This ensures that database operations are isolated.
    """
    db_path = tmp_path / "test_vault.db"
    monkeypatch.setattr("app.database.DATABASE_PATH", str(db_path))
    database.initialize_database()
    yield

class TestDatabaseInit:
    """Tests for initialize_database()."""
    
    def test_creates_tables(self):
        """All 8 tables should exist after initialization."""
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = cursor.fetchall()
        assert len(tables) == 8
        conn.close()

    def test_idempotent(self):
        """Running initialize_database() twice should not error."""
        database.initialize_database()
        
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = cursor.fetchall()
        assert len(tables) == 8
        conn.close()


class TestUserCRUD:
    """Tests for user operations."""

    def test_create_user(self):
        """Should insert a user and return user_id."""
        user_id = database.create_user("alice", "Alice Smith")
        assert user_id == 1

        conn = database.get_connection()
        user = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        assert user["username"] == "alice"
        assert user["display_name"] == "Alice Smith"
        conn.close()

    def test_duplicate_username_fails(self):
        """Should raise on duplicate username."""
        database.create_user("bob", "Bob Jones")
        with pytest.raises(sqlite3.IntegrityError):
            database.create_user("bob", "Another Bob")


class TestVaultCRUD:
    """Tests for vault operations."""

    def test_create_vault(self):
        """Should insert a vault and return vault_id."""
        user_id = database.create_user("charlie", "Charlie")
        vault_id = database.create_vault(user_id, "Personal")
        
        vault = database.load_vault(vault_id)
        assert vault is not None
        assert vault["vault_name"] == "Personal"
        assert vault["user_id"] == user_id
        assert vault["vault_status"] == "LOCKED"

    def test_create_vault_policy(self):
        """Should insert a policy row."""
        user_id = database.create_user("dave", "Dave")
        vault_id = database.create_vault(user_id, "Work")
        
        policy_id = database.create_vault_policy(vault_id, hardware_gate_required=True, software_only_enabled=False, gate_window_seconds=120)
        
        policy = database.load_vault_policy(vault_id)
        assert policy is not None
        assert policy["hardware_gate_required"] == 1
        assert policy["software_only_enabled"] == 0
        assert policy["gate_window_seconds"] == 120


class TestAuthCredentialsCRUD:
    """Tests for auth credential operations."""

    def test_save_and_load(self):
        """Should save and load auth credentials."""
        user_id = database.create_user("eve", "Eve")
        vault_id = database.create_vault(user_id, "Secrets")
        
        kdf_params = {
            "kdf_name": "argon2id",
            "kdf_memory_cost": 65536,
            "kdf_time_cost": 3,
            "kdf_parallelism": 4
        }
        
        database.save_auth_credentials(
            vault_id,
            "salt123",
            "wrapped_key_data",
            "wrapped_key_nonce",
            kdf_params
        )
        
        creds = database.load_auth_credentials(vault_id)
        assert creds is not None
        assert creds["passphrase_salt"] == "salt123"
        assert creds["wrapped_master_key"] == "wrapped_key_data"
        assert creds["kdf_memory_cost"] == 65536


class TestHardwareAuthCRUD:
    """Tests for hardware auth operations."""

    def test_save_and_load(self):
        """Should save and load hardware auth."""
        user_id = database.create_user("frank", "Frank")
        vault_id = database.create_vault(user_id, "Safe")
        
        database.save_hardware_auth(vault_id, "pin_hash", "pin_salt")
        
        hw_auth = database.load_hardware_auth(vault_id)
        assert hw_auth is not None
        assert hw_auth["keypad_pin_hash"] == "pin_hash"
        assert hw_auth["failed_attempts"] == 0

    def test_increment_failed_attempts(self):
        """Should increment the failed_attempts counter."""
        user_id = database.create_user("george", "George")
        vault_id = database.create_vault(user_id, "Vault1")
        database.save_hardware_auth(vault_id, "hash", "salt")
        
        assert database.get_failed_pin_attempts(vault_id) == 0
        
        database.increment_failed_pin_attempts(vault_id)
        assert database.get_failed_pin_attempts(vault_id) == 1
        
        database.increment_failed_pin_attempts(vault_id)
        assert database.get_failed_pin_attempts(vault_id) == 2

    def test_reset_failed_attempts(self):
        """Should reset failed_attempts to 0."""
        user_id = database.create_user("hannah", "Hannah")
        vault_id = database.create_vault(user_id, "Vault2")
        database.save_hardware_auth(vault_id, "hash", "salt")
        
        database.increment_failed_pin_attempts(vault_id)
        database.increment_failed_pin_attempts(vault_id)
        
        database.reset_failed_pin_attempts(vault_id)
        assert database.get_failed_pin_attempts(vault_id) == 0


class TestVaultDataCRUD:
    """Tests for vault data operations."""

    def test_save_and_load(self):
        """Should save and load encrypted blob."""
        user_id = database.create_user("ian", "Ian")
        vault_id = database.create_vault(user_id, "DataVault")
        
        database.save_vault_data(vault_id, "encrypted_blob", "nonce123")
        
        data = database.load_vault_data(vault_id)
        assert data is not None
        assert data["encrypted_blob"] == "encrypted_blob"
        assert data["nonce"] == "nonce123"
        assert data["algorithm"] == "xchacha20-poly1305"

    def test_update_vault_data(self):
        """Should update the encrypted blob."""
        user_id = database.create_user("jane", "Jane")
        vault_id = database.create_vault(user_id, "DataVault2")
        
        database.save_vault_data(vault_id, "old_blob", "old_nonce")
        database.update_vault_data(vault_id, "new_blob", "new_nonce")
        
        data = database.load_vault_data(vault_id)
        assert data is not None
        assert data["encrypted_blob"] == "new_blob"
        assert data["nonce"] == "new_nonce"


class TestAccessLogs:
    """Tests for access log operations."""

    def test_write_access_log(self):
        """Should insert a log entry."""
        user_id = database.create_user("kevin", "Kevin")
        vault_id = database.create_vault(user_id, "LogVault")
        
        log_id = database.write_access_log(
            vault_id, user_id, "LOGIN", "PASSWORD", True, "Success login"
        )
        assert log_id == 1
        
        logs = database.get_access_logs(vault_id=vault_id)
        assert len(logs) == 1
        assert logs[0]["event_type"] == "LOGIN"
        assert logs[0]["success"] == 1
