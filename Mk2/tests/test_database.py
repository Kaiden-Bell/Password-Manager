"""
test_database.py — Tests for the database module.

Run with:
    python -m pytest tests/test_database.py -v
"""

import pytest
import psycopg2
from app.database import db
from app.config import BASE_DIR

@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch, tmp_path):
    """
    Sets up a temporary SQLite database for each test.
    This ensures that database operations are isolated.
    """
    db_url = "postgresql://postgres:postgres@localhost:5433/vault_test_db"
    monkeypatch.setattr("app.database.DATABASE_URL", db_url)
    db.db_url = db_url
    try:
        db.initialize_database()
    except psycopg2.OperationalError:
        pass
    yield

class TestDatabaseInit:
    """Tests for db.initialize_database()."""
    
    def test_creates_tables(self):
        """All 8 tables should exist after initialization."""
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
        tables = cursor.fetchall()
        assert len(tables) == 8
        conn.close()

    def test_idempotent(self):
        """Running db.initialize_database() twice should not error."""
        db.initialize_database()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
        tables = cursor.fetchall()
        assert len(tables) == 8
        conn.close()


class TestUserCRUD:
    """Tests for user operations."""

    def test_create_user(self):
        """Should insert a user and return user_id."""
        user_id = db.create_user("alice", "Alice Smith")
        assert user_id == 1

        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        assert user["username"] == "alice"
        assert user["display_name"] == "Alice Smith"
        conn.close()

    def test_duplicate_username_fails(self):
        """Should raise on duplicate username."""
        db.create_user("bob", "Bob Jones")
        with pytest.raises(psycopg2.IntegrityError):
            db.create_user("bob", "Another Bob")


class TestVaultCRUD:
    """Tests for vault operations."""

    def test_create_vault(self):
        """Should insert a vault and return vault_id."""
        user_id = db.create_user("charlie", "Charlie")
        vault_id = db.create_vault(user_id, "Personal")
        
        vault = db.load_vault(vault_id)
        assert vault is not None
        assert vault["vault_name"] == "Personal"
        assert vault["user_id"] == user_id
        assert vault["vault_status"] == "LOCKED"

    def test_create_vault_policy(self):
        """Should insert a policy row."""
        user_id = db.create_user("dave", "Dave")
        vault_id = db.create_vault(user_id, "Work")
        
        policy_id = db.create_vault_policy(vault_id, hardware_gate_required=True, software_only_enabled=False, gate_window_seconds=120)
        
        policy = db.load_vault_policy(vault_id)
        assert policy is not None
        assert policy["hardware_gate_required"] == 1
        assert policy["software_only_enabled"] == 0
        assert policy["gate_window_seconds"] == 120


class TestAuthCredentialsCRUD:
    """Tests for auth credential operations."""

    def test_save_and_load(self):
        """Should save and load auth credentials."""
        user_id = db.create_user("eve", "Eve")
        vault_id = db.create_vault(user_id, "Secrets")
        
        kdf_params = {
            "kdf_name": "argon2id",
            "kdf_memory_cost": 65536,
            "kdf_time_cost": 3,
            "kdf_parallelism": 4
        }
        
        db.save_auth_credentials(
            vault_id,
            "salt123",
            "wrapped_key_data",
            "wrapped_key_nonce",
            kdf_params
        )
        
        creds = db.load_auth_credentials(vault_id)
        assert creds is not None
        assert creds["passphrase_salt"] == "salt123"
        assert creds["wrapped_master_key"] == "wrapped_key_data"
        assert creds["kdf_memory_cost"] == 65536


class TestHardwareAuthCRUD:
    """Tests for hardware auth operations."""

    def test_save_and_load(self):
        """Should save and load hardware auth."""
        user_id = db.create_user("frank", "Frank")
        vault_id = db.create_vault(user_id, "Safe")
        
        db.save_hardware_auth(vault_id, "pin_hash", "pin_salt")
        
        hw_auth = db.load_hardware_auth(vault_id)
        assert hw_auth is not None
        assert hw_auth["keypad_pin_hash"] == "pin_hash"
        assert hw_auth["failed_attempts"] == 0

    def test_increment_failed_attempts(self):
        """Should increment the failed_attempts counter."""
        user_id = db.create_user("george", "George")
        vault_id = db.create_vault(user_id, "Vault1")
        db.save_hardware_auth(vault_id, "hash", "salt")
        
        assert db.get_failed_pin_attempts(vault_id) == 0
        
        db.increment_failed_pin_attempts(vault_id)
        assert db.get_failed_pin_attempts(vault_id) == 1
        
        db.increment_failed_pin_attempts(vault_id)
        assert db.get_failed_pin_attempts(vault_id) == 2

    def test_reset_failed_attempts(self):
        """Should reset failed_attempts to 0."""
        user_id = db.create_user("hannah", "Hannah")
        vault_id = db.create_vault(user_id, "Vault2")
        db.save_hardware_auth(vault_id, "hash", "salt")
        
        db.increment_failed_pin_attempts(vault_id)
        db.increment_failed_pin_attempts(vault_id)
        
        db.reset_failed_pin_attempts(vault_id)
        assert db.get_failed_pin_attempts(vault_id) == 0

class TestVaultDataCRUD:

    def test_save_and_load(self):
        """Should save and load encrypted blob."""
        user_id = db.create_user("ian", "Ian")
        vault_id = db.create_vault(user_id, "DataVault")
        
        db.save_vault_data(vault_id, "encrypted_blob", "nonce123")
        
        data = db.load_vault_data(vault_id)
        assert data is not None
        assert data["encrypted_blob"] == "encrypted_blob"
        assert data["nonce"] == "nonce123"
        assert data["algorithm"] == "xchacha20-poly1305"

    def test_update_vault_data(self):
        """Should update the encrypted blob."""
        user_id = db.create_user("jane", "Jane")
        vault_id = db.create_vault(user_id, "DataVault2")
        
        db.save_vault_data(vault_id, "old_blob", "old_nonce")
        db.update_vault_data(vault_id, "new_blob", "new_nonce")
        
        data = db.load_vault_data(vault_id)
        assert data is not None
        assert data["encrypted_blob"] == "new_blob"
        assert data["nonce"] == "new_nonce"


class TestAccessLogs:
    """Tests for access log operations."""

    def test_write_access_log(self):
        """Should insert a log entry."""
        user_id = db.create_user("kevin", "Kevin")
        vault_id = db.create_vault(user_id, "LogVault")
        
        log_id = db.write_access_log(
            vault_id, user_id, "LOGIN", "PASSWORD", True, "Success login"
        )
        assert log_id == 1
        
        logs = db.get_access_logs(vault_id=vault_id)
        assert len(logs) == 1
        assert logs[0]["event_type"] == "LOGIN"
        assert logs[0]["success"] == 1
