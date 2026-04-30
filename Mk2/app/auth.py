"""
auth.py — Auth Service

Manages vault init + unlock seq.
auth.py -> crypto, database, session, and vault modules.

Security:
    - "Hardware mode" reqs a passphrase window to unlock.
    - "Software-only mode" works ONLY if vault was initalized without passcode.
    - Unlocking => passphrase -> wrapping key -> unwrap master key -> decrypt vault data -> create session.
    - Never store raw passphrases or PINs.
"""

import base64
from app import crypto, database, session, vault
from app.config import (
    ARGON2_MEMORY_COST,
    ARGON2_TIME_COST,
    ARGON2_PARALLELISM,
    KEY_LENGTH,
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
    Full vault initialization flow.
    """
    kdf_params = {
        "memory_cost": ARGON2_MEMORY_COST,
        "time_cost": ARGON2_TIME_COST,
        "parallelism": ARGON2_PARALLELISM,
    }

    user = database.create_user(username, display_name)
    vault_id = database.create_vault(user, vault_name)
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
    # encrypt_xchacha20_poly1305 takes bytes, so json dump first?
    # Wait, vault.create_empty_vault() returns a dict. crypto.encrypt_xchacha20_poly1305 takes plaintext_bytes.
    # We should json.dumps(empty_vault).encode('utf-8')
    import json
    empty_vault_bytes = json.dumps(empty_vault).encode("utf-8")
    encrypted_vault_blob, nonce = crypto.encrypt_xchacha20_poly1305(empty_vault_bytes, master_key)
    database.save_vault_data(vault_id, encrypted_vault_blob, nonce)
    database.write_access_log(vault_id, "initialize", "hardware_gated", True, "Vault initialized")
    return {"user_id": user, "vault_id": vault_id, "success": True}

# --------------
# Hardware PIN |
# --------------


def verify_hardware_pin(vault_id: int, pin_attempt: str) -> bool:
    """
    Verify a keypad PIN attempt against the stored hash.
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


# # -------------
# Passphrase Seq
# # -------------


def open_passphrase_window(vault_id: int) -> None:
    """
    Open the temporary passphrase-entry window for a vault.
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
    Check whether the passphrase window is currently open.
    """
    return session.is_passphrase_window_active(vault_id)


# # -------------
# Unlock Seq
# -------------

def unlock_with_passphrase(
    vault_id: int,
    passphrase: str,
    auth_method: str = "hardware_gated",
) -> dict:
    """
    Hardware-gated passphrase unlock.

    Precondition: passphrase window MUST be active.

    Steps:
        1. Verify passphrase window is active.
        2. Load auth credentials from database.
        3. Decode the passphrase salt.
        4. Derive wrapping key via crypto.derive_key_argon2id().
        5. Unwrap master key via crypto.unwrap_master_key().
        6. Decrypt vault data via vault.load_decrypted_vault().
        7. Create session via session.create_session().
        8. Write access log.

    Returns:
        Dict with success status.

    Raises:
        ValueError: If passphrase window is not active.
        CryptoError: If passphrase is incorrect.

    TODO: Implement the hardware-gated unlock flow.
    """

    if not is_passphrase_window_active(vault_id):
        raise ValueError(f"Passphrase window is not active for vault {vault_id}")

    vault_policy = database.load_vault_policy(vault_id)
    if not vault_policy:
        raise ValueError(f"No vault policy found for vault {vault_id}")
    if not vault_policy["hardware_gate_required"]:
        raise ValueError(f"Hardware gating is not enabled for vault {vault_id}")
    if not session.is_passphrase_window_active(vault_id):
        raise ValueError(f"Passphrase window is not active for vault {vault_id}")

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
    master_key = crypto.unwrap_master_key(wrapped_master_key, wrapped_nonce, wrapping_key)
    vault_data = vault.load_decrypted_vault(vault_id, master_key)
    session.create_session(vault_id, vault_data, master_key)
    database.write_access_log(vault_id, "unlock", auth_method, True, "Vault unlocked")

    return {"success": True}


def unlock_software_only(vault_id: int, passphrase: str) -> dict:
    """
    Software-only passphrase unlock.

    Precondition: vault policy must allow software-only mode.

    Steps:
        1. Load vault policy from database.
        2. Verify software_only_enabled is True.
        3. Load auth credentials from database.
        4. Decode the passphrase salt.
        5. Derive wrapping key via crypto.derive_key_argon2id().
        6. Unwrap master key via crypto.unwrap_master_key().
        7. Decrypt vault data via vault.load_decrypted_vault().
        8. Create session via session.create_session().
        9. Write access log.

    Returns:
        Dict with success status.

    Raises:
        ValueError: If software-only mode is not enabled.
        CryptoError: If passphrase is incorrect.

    TODO: Implement the software-only unlock flow.
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
    master_key = crypto.unwrap_master_key(wrapped_master_key, wrapped_nonce, wrapping_key)
    vault_data = vault.load_decrypted_vault(vault_id, master_key)
    session.create_session(vault_id, vault_data, master_key)
    database.write_access_log(vault_id, "unlock", "software_only", True, "Vault unlocked")

    return {"success": True}
