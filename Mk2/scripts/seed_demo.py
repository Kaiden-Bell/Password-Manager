"""
seed_demo.py — Seed the database with demo data for testing.

Calls auth.initialize_vault() with sample values.
Run from project root:
    python scripts/seed_demo.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import db
from app.auth import initialize_vault


def main():
    # Ensure database exists
    db.initialize_database()

    print("Seeding demo vault...")

    # TODO: Uncomment once auth.initialize_vault() is implemented.
    # result = initialize_vault(
    #     username="demo_user",
    #     display_name="Demo User",
    #     vault_name="My Vault",
    #     passphrase="correct-horse-battery-staple",
    #     keypad_pin="122004",               # Optional hardware PIN
    #     hardware_gate_required=False,
    #     software_only_enabled=True,
    # )
    # print(f"Demo vault created: {result}")

    print("seed_demo.py: initialize_vault() not yet implemented.")
    print("Uncomment the call above once auth.py is complete.")


if __name__ == "__main__":
    main()
