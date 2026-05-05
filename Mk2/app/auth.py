"""
auth.py — Auth Service

Manages vault init + unlock seq.
Requires: crypto, database, session, and vault modules.

"""

import base64
import json
from app import crypto, database, session, vault
from app.config import (
    ARGON2_MEMORY_COST,
    ARGON2_TIME_COST,
    ARGON2_PARALLELISM,
)

# ------------
# Vault Init |
# ------------

def initialize_vault(
    username: str,
    display_name: str,
    vault_name: str,
    passphrase: str,
    keypad_pin: str | None = None,
    hardware_gate_required: bool = False,
    software_only_enabled: bool = True,
) -> dict:
    """
        Desc: Full vault initialization flow.
        Arguments: username, display_name, vault_name, passphrase, keypad_pin, hardware_gate_required, software_only_enabled
        Returns: dict, vault id and success status
    """
    kdf_params = {
        "memory_cost": ARGON2_MEMORY_COST,
        "time_cost": ARGON2_TIME_COST,
        "parallelism": ARGON2_PARALLELISM,
    }

    user_record = database.get_user_by_username(username)
    if user_record:
        user_id = user_record["user_id"]
        existing_vaults = database.get_user_vaults(username)
        if any(v["vault_name"].lower() == vault_name.lower() for v in existing_vaults):
            raise ValueError(f"A vault named '{vault_name}' already exists for user '{username}'.")
    else:
        user_id = database.create_user(username, display_name)

    vault_id = database.create_vault(user_id, vault_name)
    vault_policy = database.create_vault_policy(vault_id, hardware_gate_required, software_only_enabled) 
    master_key = crypto.generate_master_key()
    passphrase_salt_bytes = crypto.generate_salt()
    wrapping_key = crypto.derive_key_argon2id(passphrase, passphrase_salt_bytes)
    wrapped_master_key, wrapped_nonce = crypto.wrap_master_key(master_key, wrapping_key)
    
    passphrase_salt_b64 = base64.b64encode(passphrase_salt_bytes).decode("utf-8")
    database.save_auth_credentials(vault_id, passphrase_salt_b64, wrapped_master_key, wrapped_nonce, kdf_params)

    if keypad_pin:
        pin_salt_bytes = crypto.generate_salt()
        hashed_pin = crypto.hash_keypad_pin(keypad_pin, pin_salt_bytes)
        pin_salt_b64 = base64.b64encode(pin_salt_bytes).decode("utf-8")
        database.save_hardware_auth(vault_id, hashed_pin, pin_salt_b64)

    empty_vault = vault.create_empty_vault()

    empty_vault_bytes = json.dumps(empty_vault).encode("utf-8")
    encrypted_vault_blob, nonce = crypto.encrypt_xchacha20_poly1305(empty_vault_bytes, master_key)
    database.save_vault_data(vault_id, encrypted_vault_blob, nonce)
    database.write_access_log(vault_id, user_id, "initialize", "hardware_gated", True, "Vault initialized")
    return {"user_id": user_id, "vault_id": vault_id, "success": True}

# --------------
# Hardware PIN |
# --------------

def verify_hardware_pin(vault_id: int, pin_attempt: str) -> bool:
    """
        Desc: Verify a keypad PIN attempt against the stored hash.
        Arguments: vault_id, pin_attempt
        Returns: bool, True if PIN is correct, False otherwise
    """
    hardware_auth = database.load_hardware_auth(vault_id)

    if not hardware_auth:
        return False

    salt = crypto.base64.b64decode(hardware_auth["keypad_pin_salt"])
    stored_hash = hardware_auth["keypad_pin_hash"]
    
    if crypto.verify_keypad_pin(pin_attempt, stored_hash, salt):
        session.open_passphrase_window(vault_id)
        database.reset_failed_pin_attempts(vault_id)
        return True

    else:
        database.increment_failed_pin_attempts(vault_id)
        if database.get_failed_pin_attempts(vault_id) >= 3:
            database.lock_vault(vault_id)
            
        return False

# ----------------
# Passphrase Seq |
# ----------------

def open_passphrase_window(vault_id: int) -> None:
    """
        Desc: Open the temporary passphrase-entry window for a vault.
        Arguments: vault_id
        Returns: None
    """
    vault_policy = database.load_vault_policy(vault_id)
    if not vault_policy:
        raise ValueError(f"No vault policy found for vault {vault_id}")
    if not vault_policy["hardware_gate_required"]:
        raise ValueError(f"Hardware gating is not enabled for vault {vault_id}")
    if session.is_passphrase_window_active(vault_id):
        return
    session.open_passphrase_window(vault_id)
    database.reset_failed_pin_attempts(vault_id)

def is_passphrase_window_active(vault_id: int) -> bool:
    """
        Desc: Check whether the passphrase window is currently open.
        Arguments: vault_id
        Returns: bool, True if passphrase window is open, False otherwise
    """
    return session.is_passphrase_window_active(vault_id)

# ------------
# Unlock Seq |
# ------------

def unlock_with_passphrase(
    vault_id: int,
    passphrase: str,
    auth_method: str = "hardware_gated",
) -> dict:
    """
        Desc: Hardware-gated passphrase unlock. (PASSPHRASE WINDOW MUST BE ACTIVE)
        Arguments: vault_id, passphrase, auth_method
        Returns: dict, session data and vault id
    """
    if not is_passphrase_window_active(vault_id):
        raise ValueError(f"Passphrase window is not active for vault {vault_id}")

    vault_policy = database.load_vault_policy(vault_id)
    if not vault_policy: raise ValueError(f"No vault policy found for vault {vault_id}")
    if not vault_policy["hardware_gate_required"]: raise ValueError(f"Hardware gating is not enabled for vault {vault_id}")
    if not session.is_passphrase_window_active(vault_id): raise ValueError(f"Passphrase window is not active for vault {vault_id}")

    auth_credentials = database.load_auth_credentials(vault_id)
    passphrase_salt_b64 = auth_credentials["passphrase_salt"]
    passphrase_salt_bytes = base64.b64decode(passphrase_salt_b64)
    wrapped_master_key = auth_credentials["wrapped_master_key"]
    wrapped_nonce = auth_credentials["wrapped_master_key_nonce"]
    
    wrapping_key = crypto.derive_key_argon2id(
        passphrase, 
        passphrase_salt_bytes,
        memory_cost=auth_credentials["kdf_memory_cost"],
        time_cost=auth_credentials["kdf_time_cost"],
        parallelism=auth_credentials["kdf_parallelism"]
    )
    try:
        master_key = crypto.unwrap_master_key(wrapped_master_key, wrapped_nonce, wrapping_key)
    except crypto.CryptoError:
        database.write_access_log(vault_id, None, "unlock", auth_method, False, "Invalid passphrase")
        raise ValueError("Invalid passphrase")
        
    vault_data = vault.load_decrypted_vault(vault_id, master_key)
    vault_record = database.load_vault(vault_id)
    user_id = vault_record["user_id"] if vault_record else None
    session.create_session(user_id, vault_id, auth_method, vault_data, master_key)
    database.write_access_log(vault_id, user_id, "unlock", auth_method, True, "Vault unlocked")

    return {"success": True}


def unlock_software_only(vault_id: int, passphrase: str) -> dict:
    """
        Desc: Software-only passphrase unlock.
        Arguments: vault_id, passphrase
        Returns: dict, session data and vault id
    """

    vault_policy = database.load_vault_policy(vault_id)
    if not vault_policy:
        raise ValueError(f"No vault policy found for vault {vault_id}")
    if not vault_policy["software_only_enabled"]:
        raise ValueError(f"Software-only mode is not enabled for vault {vault_id}")

    auth_credentials = database.load_auth_credentials(vault_id)
    passphrase_salt_b64 = auth_credentials["passphrase_salt"]
    passphrase_salt_bytes = base64.b64decode(passphrase_salt_b64)
    wrapped_master_key = auth_credentials["wrapped_master_key"]
    wrapped_nonce = auth_credentials["wrapped_master_key_nonce"]
    
    wrapping_key = crypto.derive_key_argon2id(
        passphrase, 
        passphrase_salt_bytes,
        memory_cost=auth_credentials["kdf_memory_cost"],
        time_cost=auth_credentials["kdf_time_cost"],
        parallelism=auth_credentials["kdf_parallelism"]
    )
    try:
        master_key = crypto.unwrap_master_key(wrapped_master_key, wrapped_nonce, wrapping_key)
    except crypto.CryptoError:
        database.write_access_log(vault_id, None, "unlock", "software_only", False, "Invalid passphrase")
        raise ValueError("Invalid passphrase")
        
    vault_data = vault.load_decrypted_vault(vault_id, master_key)
    vault_record = database.load_vault(vault_id)
    user_id = vault_record["user_id"] if vault_record else None
    session.create_session(user_id, vault_id, "software_only", vault_data, master_key)
    database.write_access_log(vault_id, user_id, "unlock", "software_only", True, "Vault unlocked")

    return {"success": True}
