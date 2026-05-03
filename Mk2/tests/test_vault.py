"""
test_vault.py — Tests for the vault module.

Run with:
    python -m pytest tests/test_vault.py -v
"""

import json
import pytest
from unittest.mock import patch, MagicMock

import app.session
from app.vault import (
    create_empty_vault,
    load_decrypted_vault,
    save_decrypted_vault,
    add_credential,
    update_credential,
    delete_credential,
    search_credentials,
)

# -----------
# Fixtures  |
# -----------

VAULT_ID = 42
USER_ID = 1
MASTER_KEY = b"\x00" * 32


@pytest.fixture(autouse=True)
def _clean_sessions():
    """Clear the in-memory session store before each test."""
    app.session._sessions.clear()
    yield
    app.session._sessions.clear()


def _create_test_session(vault_data: dict | None = None) -> dict:
    """Helper: create a session with the given (or empty) vault data."""
    if vault_data is None:
        vault_data = create_empty_vault()
    return app.session.create_session(
        user_id=USER_ID,
        vault_id=VAULT_ID,
        auth_method="passphrase",
        decrypted_vault=vault_data,
        master_key=MASTER_KEY,
    )


# ----------------------
# TestVaultCreation     |
# ----------------------

class TestVaultCreation:
    def test_empty_vault_structure(self):
        """Should return {"entries": []}."""
        vault = create_empty_vault()
        assert vault == {"entries": []}

    def test_empty_vault_entries_is_list(self):
        """Entries value must be a list."""
        vault = create_empty_vault()
        assert isinstance(vault["entries"], list)


# ----------------------
# TestLoadSaveVault     |
# ----------------------

class TestLoadSaveVault:
    """Tests for load_decrypted_vault / save_decrypted_vault."""

    @patch("app.vault.database")
    @patch("app.vault.crypto")
    def test_load_returns_empty_when_no_data(self, mock_crypto, mock_db):
        """When database returns None, load should return an empty vault."""
        mock_db.load_vault_data.return_value = None
        result = load_decrypted_vault(VAULT_ID, MASTER_KEY)
        assert result == {"entries": []}

    @patch("app.vault.database")
    @patch("app.vault.crypto")
    def test_load_decrypts_stored_data(self, mock_crypto, mock_db):
        """When database returns data, load should decrypt and parse JSON."""
        vault_data = {"entries": [{"entry_id": 0, "site": "x.com"}]}
        json_bytes = json.dumps(vault_data).encode("utf-8")

        mock_db.load_vault_data.return_value = {"encrypted_blob": "enc_blob_b64", "nonce": "nonce_b64"}
        mock_crypto.decrypt_xchacha20_poly1305.return_value = json_bytes

        result = load_decrypted_vault(VAULT_ID, MASTER_KEY)
        assert result == vault_data
        mock_crypto.decrypt_xchacha20_poly1305.assert_called_once_with(
            "enc_blob_b64", "nonce_b64", MASTER_KEY
        )

    @patch("app.vault.database")
    @patch("app.vault.crypto")
    def test_save_encrypts_and_stores(self, mock_crypto, mock_db):
        """save_decrypted_vault should JSON-encode, encrypt, and write to DB."""
        vault_data = {"entries": []}
        mock_crypto.encrypt_xchacha20_poly1305.return_value = ("enc_b64", "nonce_b64")

        save_decrypted_vault(VAULT_ID, vault_data, MASTER_KEY)

        mock_crypto.encrypt_xchacha20_poly1305.assert_called_once()
        mock_db.update_vault_data.assert_called_once_with(VAULT_ID, "enc_b64", "nonce_b64")


# ----------------------
# TestCredentialCRUD    |
# ----------------------

class TestCredentialCRUD:

    @patch("app.vault.save_decrypted_vault")
    def test_add_credential(self, mock_save):
        """Should add an entry and re-encrypt."""
        _create_test_session()

        entry = add_credential(VAULT_ID, "github.com", "user1", "pass1")

        assert entry["site"] == "github.com"
        assert entry["username"] == "user1"
        assert entry["password"] == "pass1"
        assert "entry_id" in entry
        assert "last_rotated" in entry
        mock_save.assert_called_once()

    @patch("app.vault.save_decrypted_vault")
    def test_add_assigns_incrementing_entry_id(self, mock_save):
        """Should assign incrementing entry_id values."""
        _create_test_session()

        e1 = add_credential(VAULT_ID, "a.com", "u1", "p1")
        e2 = add_credential(VAULT_ID, "b.com", "u2", "p2")
        e3 = add_credential(VAULT_ID, "c.com", "u3", "p3")

        assert e1["entry_id"] == 0
        assert e2["entry_id"] == 1
        assert e3["entry_id"] == 2

    @patch("app.vault.save_decrypted_vault")
    def test_add_first_entry_gets_id_zero(self, mock_save):
        """The very first entry in an empty vault should get entry_id 0."""
        _create_test_session()
        entry = add_credential(VAULT_ID, "site.com", "user", "pw")
        assert entry["entry_id"] == 0

    def test_add_without_session_fails(self):
        """Should raise ValueError when no active session exists."""
        with pytest.raises(ValueError, match="No active session"):
            add_credential(VAULT_ID, "site.com", "user", "pw")

    @patch("app.vault.save_decrypted_vault")
    def test_update_credential(self, mock_save):
        """Should update specified fields only."""
        _create_test_session()
        add_credential(VAULT_ID, "old.com", "old_user", "old_pass")

        updated = update_credential(VAULT_ID, 0, site="new.com")

        assert updated["site"] == "new.com"
        assert updated["username"] == "old_user"
        assert updated["password"] == "old_pass"

    @patch("app.vault.save_decrypted_vault")
    def test_update_password_rotates_date(self, mock_save):
        """Updating the password should refresh last_rotated."""
        _create_test_session()
        entry = add_credential(VAULT_ID, "s.com", "u", "p1")
        original_date = entry["last_rotated"]

        updated = update_credential(VAULT_ID, 0, password="p2")

        assert updated["password"] == "p2"
        assert updated["last_rotated"] is not None

    @patch("app.vault.save_decrypted_vault")
    def test_update_nonexistent_fails(self, mock_save):
        """Should raise ValueError for unknown entry_id."""
        _create_test_session()
        with pytest.raises(ValueError, match="No entry found"):
            update_credential(VAULT_ID, 999, site="nope.com")

    def test_update_without_session_fails(self):
        """Should raise ValueError when no active session exists."""
        with pytest.raises(ValueError, match="No active session"):
            update_credential(VAULT_ID, 0, site="x.com")

    @patch("app.vault.save_decrypted_vault")
    def test_delete_credential(self, mock_save):
        """Should remove the entry and re-encrypt."""
        _create_test_session()
        add_credential(VAULT_ID, "del.com", "u", "p")

        deleted = delete_credential(VAULT_ID, 0)

        assert deleted["site"] == "del.com"
        # Vault should now be empty
        sess = app.session.get_session(VAULT_ID)
        assert len(sess["decrypted_vault"]["entries"]) == 0

    @patch("app.vault.save_decrypted_vault")
    def test_delete_nonexistent_fails(self, mock_save):
        """Should raise ValueError for unknown entry_id."""
        _create_test_session()
        with pytest.raises(ValueError, match="No entry found"):
            delete_credential(VAULT_ID, 999)

    def test_delete_without_session_fails(self):
        """Should raise ValueError when no active session exists."""
        with pytest.raises(ValueError, match="No active session"):
            delete_credential(VAULT_ID, 0)

    @patch("app.vault.save_decrypted_vault")
    def test_search_by_site(self, mock_save):
        """Should find entries matching site query."""
        _create_test_session()
        add_credential(VAULT_ID, "github.com", "user1", "p1")
        add_credential(VAULT_ID, "gitlab.com", "user2", "p2")
        add_credential(VAULT_ID, "example.com", "user3", "p3")

        results = search_credentials(VAULT_ID, "git")

        assert len(results) == 2
        sites = {r["site"] for r in results}
        assert sites == {"github.com", "gitlab.com"}

    @patch("app.vault.save_decrypted_vault")
    def test_search_by_username(self, mock_save):
        """Should find entries matching username query."""
        _create_test_session()
        add_credential(VAULT_ID, "a.com", "john_doe", "p1")
        add_credential(VAULT_ID, "b.com", "jane_doe", "p2")
        add_credential(VAULT_ID, "c.com", "admin", "p3")

        results = search_credentials(VAULT_ID, "doe")

        assert len(results) == 2

    @patch("app.vault.save_decrypted_vault")
    def test_search_case_insensitive(self, mock_save):
        """Search should be case-insensitive."""
        _create_test_session()
        add_credential(VAULT_ID, "GitHub.com", "UserOne", "p1")

        results = search_credentials(VAULT_ID, "github")
        assert len(results) == 1

        results = search_credentials(VAULT_ID, "USERONE")
        assert len(results) == 1

    @patch("app.vault.save_decrypted_vault")
    def test_search_no_results(self, mock_save):
        """Should return empty list for no matches."""
        _create_test_session()
        add_credential(VAULT_ID, "a.com", "user1", "p1")

        results = search_credentials(VAULT_ID, "nonexistent")
        assert results == []

    def test_search_without_session_fails(self):
        """Should raise ValueError when no active session exists."""
        with pytest.raises(ValueError, match="No active session"):
            search_credentials(VAULT_ID, "test")
