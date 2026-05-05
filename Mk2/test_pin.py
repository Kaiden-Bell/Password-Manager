import sys
from app.database import initialize_database, get_connection
from app.auth import initialize_vault, verify_hardware_pin
import os
import shutil

# Reset DB
db_path = "data/vault.db"
if os.path.exists(db_path):
    os.remove(db_path)

initialize_database()

print("Initializing vault...")
res = initialize_vault(
    username="testuser",
    vault_name="testvault",
    passphrase="password123",
    keypad_pin="123456",
    hardware_gate_required=True,
    software_only_enabled=False
)
vault_id = res['vault_id']
print("Vault ID:", vault_id)

print("Verifying correct pin:")
success = verify_hardware_pin(vault_id, "123456")
print("Success:", success)

print("Verifying wrong pin:")
wrong = verify_hardware_pin(vault_id, "000000")
print("Wrong:", wrong)
