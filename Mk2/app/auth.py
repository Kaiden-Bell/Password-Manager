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

# from app import crypto, database, session, vault
# from app.config import (
#     ARGON2_MEMORY_COST,
#     ARGON2_TIME_COST,
#     ARGON2_PARALLELISM,
#     KEY_LENGTH,
# )


# # -------------
# Vault Init
# # -------------

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

    Steps:
        1. Create user via database.create_user().
        2. Create vault via database.create_vault().
        3. Create vault policy via database.create_vault_policy().
        4. Generate a random vault master key via crypto.generate_master_key().
        5. Generate a passphrase salt via crypto.generate_salt().
        6. Derive wrapping key via crypto.derive_key_argon2id(passphrase, salt).
        7. Wrap master key via crypto.wrap_master_key().
        8. Save auth credentials via database.save_auth_credentials().
        9. If keypad_pin is provided:
           a. Generate PIN salt.
           b. Hash PIN via crypto.hash_keypad_pin().
           c. Save via database.save_hardware_auth().
        10. Create empty vault data via vault.create_empty_vault().
        11. Encrypt empty vault via crypto.encrypt_xchacha20_poly1305().
        12. Save encrypted vault via database.save_vault_data().
        13. Write access log.

    Returns:
        Dict with user_id, vault_id, and success status.

    TODO: Implement the full flow described above.
    """
    raise NotImplementedError("initialize_vault")


# # -------------
# Hardware PIN
# # -------------


def verify_hardware_pin(vault_id: int, pin_attempt: str) -> bool:
    """
    Verify a keypad PIN attempt against the stored hash.

    Steps:
        1. Load hardware_auth from database.
        2. Decode the stored salt.
        3. Call crypto.verify_keypad_pin().
        4. If valid: reset failed attempts, open passphrase window.
        5. If invalid: increment failed attempts, return False.

    Returns:
        True if the PIN is correct.

    TODO: Implement PIN verification flow.
    """
    raise NotImplementedError("verify_hardware_pin")


# # -------------
# Passphrase Seq
# # -------------


def open_passphrase_window(vault_id: int) -> None:
    """
    Open the temporary passphrase-entry window for a vault.

    Delegates to session.open_passphrase_window().

    TODO: Call session.open_passphrase_window(vault_id).
    """
    raise NotImplementedError("open_passphrase_window")


def is_passphrase_window_active(vault_id: int) -> bool:
    """
    Check whether the passphrase window is currently open.

    Delegates to session.is_passphrase_window_active().

    TODO: Call and return session.is_passphrase_window_active(vault_id).
    """
    raise NotImplementedError("is_passphrase_window_active")


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
    raise NotImplementedError("unlock_with_passphrase")


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
    raise NotImplementedError("unlock_software_only")
