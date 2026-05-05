import os
import sys

from app import database
from app import auth
from app import config

config.DATABASE_PATH = os.path.abspath("test_vault.db")
database.DATABASE_PATH = config.DATABASE_PATH

if os.path.exists(config.DATABASE_PATH):
    os.remove(config.DATABASE_PATH)

database.initialize_database()

res = auth.initialize_vault(
    username="test",
    display_name="Test User",
    vault_name="Test Vault",
    passphrase="password123",
    hardware_gate_required=False,
    software_only_enabled=True,
)

vault_id = res["vault_id"]
print("Vault initialized:", vault_id)

try:
    auth.unlock_software_only(vault_id, "password123")
    print("Unlocked successfully!")
except Exception as e:
    import traceback
    traceback.print_exc()

