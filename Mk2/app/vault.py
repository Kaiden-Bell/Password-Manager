"""
vault.py — Vault data operations.

Manages the plaintext vault data structure and re-encryption after mutations.
Vault data format:

    {
        "entries": [
            {
                "entry_id": 0,
                "site": "github.com",
                "username": "example_user",
                "password": "example_password",
                "last_rotated": "2026-04-25"
            }
        ]
    }

Notes:
    - All mutation functions require an unlocked session or master key.
    - After any add/update/delete, the vault data must be re-encrypted
      and saved to the database.
"""

import json

from app import crypto, database, session
from app.password_utils import current_date_string


# ----------------
# Vault Creation |
# ----------------

def create_empty_vault() -> dict:
    """
    Return a new, empty vault data structure.
    """

    empty_vault = {
        "entries": []
    }

    return empty_vault


# -------------
# Load / Save |
# -------------

def load_decrypted_vault(vault_id: int, master_key: bytes) -> dict:
    """
    Load and decrypt vault data from the database.
    """

    result = database.load_vault_data(vault_id)

    if not result:
        return create_empty_vault()

    enc_b64, nonce_b64 = result

    decrypted_data = crypto.decrypt_xchacha20_poly1305(enc_b64, nonce_b64, master_key)
    
    vault_data = json.loads(decrypted_data)

    return vault_data


def save_decrypted_vault(
    vault_id: int,
    vault_data: dict,
    master_key: bytes,
) -> None:
    """
    Encrypt and save vault data to the database.
    """

    json_bytes = json.dumps(vault_data).encode("utf-8")
    enc_b64, nonce_b64 = crypto.encrypt_xchacha20_poly1305(json_bytes, master_key)
    database.update_vault_data(vault_id, enc_b64, nonce_b64)


# -----------------
# Credential CRUD |
# -----------------

def add_credential(
    vault_id: int,
    site: str,
    username: str,
    password: str,
) -> dict:
    """
    Add a new credential entry to the vault.
    """

    curr_session = session.get_session(vault_id)
    if not curr_session:
        raise ValueError(f"No active session found for vault {vault_id}")

    vault_data = curr_session["decrypted_vault"]
    entries = vault_data["entries"]

    if not entries:
        new_entry_id = 0
    else:
        max_id = max(entry["entry_id"] for entry in entries)
        new_entry_id = max_id + 1

    new_entry = {
        "entry_id": new_entry_id,
        "site": site,
        "username": username,
        "password": password,
        "last_rotated": current_date_string(),
    }

    entries.append(new_entry)
    save_decrypted_vault(vault_id, vault_data, curr_session["vault_master_key"])
    curr_session["decrypted_vault"] = vault_data

    return new_entry


def update_credential(
    vault_id: int,
    entry_id: int,
    site: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> dict:
    """
    Update an existing credential entry.
    """

    curr_session = session.get_session(vault_id)
    if not curr_session:
        raise ValueError(f"No active session found for vault {vault_id}")

    vault_data = curr_session["decrypted_vault"]
    entries = vault_data["entries"]

    entry_to_update = None
    for entry in entries:
        if entry["entry_id"] == entry_id:
            entry_to_update = entry
            break

    if entry_to_update is None:
        raise ValueError("No entry found with the given entry_id.")

    if site is not None:
        entry_to_update["site"] = site

    if username is not None:
        entry_to_update["username"] = username

    if password is not None:
        entry_to_update["password"] = password
        entry_to_update["last_rotated"] = current_date_string()

    save_decrypted_vault(vault_id, vault_data, curr_session["vault_master_key"])
    curr_session["decrypted_vault"] = vault_data

    return entry_to_update


def delete_credential(vault_id: int, entry_id: int) -> dict:
    """
    Delete a credential entry from the vault.
    """

    curr_session = session.get_session(vault_id)
    if not curr_session:
        raise ValueError(f"No active session found for vault {vault_id}")

    vault_data = curr_session["decrypted_vault"]
    entries = vault_data["entries"]

    target = -1
    for i, entry in enumerate(entries):
        if entry["entry_id"] == entry_id:
            target = i
            break
    
    if target == -1:
        raise ValueError(f"No entry found for vault {vault_id} with entry_id {entry_id}.")

    deleted = entries.pop(target)
    save_decrypted_vault(vault_id, vault_data, curr_session["vault_master_key"])
    curr_session["decrypted_vault"] = vault_data

    return deleted


def search_credentials(vault_id: int, query: str) -> list[dict]:
    """
    Search vault credentials by site or username.
    """

    curr_session = session.get_session(vault_id)
    if not curr_session:
        raise ValueError(f"No active session found for vault {vault_id}")

    vault_data = curr_session["decrypted_vault"]
    entries = vault_data["entries"]

    search_results = []
    for entry in entries:
        if query.lower() in entry["site"].lower() or query.lower() in entry["username"].lower():
            search_results.append(entry)

    return search_results
