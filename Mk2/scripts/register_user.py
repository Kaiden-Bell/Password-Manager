#!/usr/bin/env python3
"""
scripts/register_user.py
────────────────────────
Interactive CLI to register a new user in The Vault.

Prompts for:
  - username
  - passphrase
  - optional RFID UID + PIN

Creates:
  - User row
  - RFIDTag row (if provided)
  - VaultMeta row with wrapped master key(s)
  - Empty encrypted vault file

Usage:
    python scripts/register_user.py
"""

import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Config
from app.crypto import derive_key, generate_master_key, generate_salt, wrap_key
from app.database import get_db, init_db
from app.models import RFIDTag, User, VaultMeta
from app.vault import create_vault


def main() -> None:
    cfg = Config.from_env()
    init_db(cfg.database_url)

    print("══════════════════════════════════════════")
    print("   The Vault — User Registration")
    print("══════════════════════════════════════════\n")

    # ── Collect user info ─────────────────────────
    username = input("Username: ").strip()
    if not username:
        print("✘  Username cannot be empty.")
        sys.exit(1)

    passphrase = getpass.getpass("Passphrase: ")
    passphrase_confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != passphrase_confirm:
        print("✘  Passphrases do not match.")
        sys.exit(1)

    # ── Optional RFID ─────────────────────────────
    rfid_uid = input("\nRFID UID (leave blank to skip): ").strip().upper()
    pin = ""
    if rfid_uid:
        pin = getpass.getpass("PIN for RFID unlock: ")
        pin_confirm = getpass.getpass("Confirm PIN: ")
        if pin != pin_confirm:
            print("✘  PINs do not match.")
            sys.exit(1)

    # ── Generate crypto material ──────────────────
    master_key = generate_master_key()
    master_salt = generate_salt()

    # Passphrase path
    pp_salt = generate_salt()
    pp_hash = derive_key(passphrase, pp_salt, cfg.kdf_iterations)
    pp_wrapping_key = derive_key(passphrase, master_salt, cfg.kdf_iterations)
    wrapped_key_passphrase = wrap_key(master_key, pp_wrapping_key)

    # RFID path (optional)
    wrapped_key_rfid = None
    pin_hash = None
    pin_salt = None
    if rfid_uid and pin:
        pin_salt = generate_salt()
        pin_hash = derive_key(pin, pin_salt, cfg.kdf_iterations)
        pin_wrapping_key = derive_key(pin, master_salt, cfg.kdf_iterations)
        wrapped_key_rfid = wrap_key(master_key, pin_wrapping_key)

    # ── Persist everything ────────────────────────
    with get_db() as db:
        # Check uniqueness
        if db.query(User).filter_by(username=username).first():
            print(f"✘  Username '{username}' already exists.")
            sys.exit(1)

        user = User(
            username=username,
            passphrase_hash=pp_hash,
            passphrase_salt=pp_salt,
        )
        db.add(user)
        db.flush()  # populate user.id

        if rfid_uid and pin_hash and pin_salt:
            if db.query(RFIDTag).filter_by(uid_hex=rfid_uid).first():
                print(f"✘  RFID UID '{rfid_uid}' is already registered.")
                sys.exit(1)

            tag = RFIDTag(
                uid_hex=rfid_uid,
                user_id=user.id,
                pin_hash=pin_hash,
                pin_salt=pin_salt,
            )
            db.add(tag)

        vault_filename = f"{user.id}.vault"
        vault_meta = VaultMeta(
            user_id=user.id,
            vault_file=vault_filename,
            wrapped_key_rfid=wrapped_key_rfid,
            wrapped_key_passphrase=wrapped_key_passphrase,
            master_salt=master_salt,
        )
        db.add(vault_meta)

        # Create the encrypted vault file on disk
        create_vault(cfg.vault_dir, vault_filename, master_key)

    print(f"\n✔  User '{username}' registered successfully.")
    print(f"   Vault file: {cfg.vault_dir}/{vault_filename}")
    if rfid_uid:
        print(f"   RFID UID:   {rfid_uid}")
    print()


if __name__ == "__main__":
    main()
