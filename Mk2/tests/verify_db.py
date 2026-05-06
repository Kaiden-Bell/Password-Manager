import os
import sqlite3
from app.database import db # (
    get_connection,
    create_user,
    create_vault,
    create_vault_policy,
    save_auth_credentials,
    load_auth_credentials,
    save_hardware_auth,
    load_hardware_auth,
    increment_failed_pin_attempts,
    reset_failed_pin_attempts,
    load_vault_policy,
    save_vault_data,
    load_vault_data,
    update_vault_data,
    write_access_log
)
from app import config

TEST_DB_PATH = "data/test_db_simple.db"
from app.database import db
db.db_path = TEST_DB_PATH

def run_tests():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    testCount = 0
    print("Init DB")
    try:
        db.initialize_database()
        assert os.path.exists(TEST_DB_PATH)
        testCount += 1
    except Exception as e:
        print(f"FAILED init DB: {e}")
        raise
    
    print("User creation")
    try:
        user_id = create_user("testuser", "Test User")
        assert user_id > 0
        testCount += 1
    except Exception as e:
        print(f"FAILED user creation: {e}")
        raise
    
    print("Vault creation")
    try:
        vault_id = create_vault(user_id, "Personal Vault")
        assert vault_id > 0
        testCount += 1
    except Exception as e:
        print(f"FAILED vault creation: {e}")
        raise
    
    print("Vault policy")
    try:
        policy_id = create_vault_policy(vault_id, hardware_gate_required=True, software_only_enabled=False, gate_window_seconds=120)
        assert policy_id > 0
        policy = load_vault_policy(vault_id)
        assert policy is not None
        assert policy["hardware_gate_required"] == 1
        testCount += 1
    except Exception as e:
        print(f"FAILED vault policy: {e}")
        raise
    
    print("Auth credentials")
    kdf_params = {
        "kdf_name": "argon2id",
        "kdf_memory_cost": 65536,
        "kdf_time_cost": 3,
        "kdf_parallelism": 4
    }
    try:
        auth_id = save_auth_credentials(vault_id, "salt", "wrapped_key", "nonce", kdf_params)
        assert auth_id > 0
        creds = load_auth_credentials(vault_id)
        assert creds is not None
        assert creds["passphrase_salt"] == "salt"
        testCount += 1
    except Exception as e:
        print(f"FAILED auth credentials: {e}")
        raise
    
    print("Hardware auth")
    try:
        save_hardware_auth(vault_id, "pin_hash", "pin_salt")
        auth = load_hardware_auth(vault_id)
        assert auth is not None
        increment_failed_pin_attempts(vault_id)
        auth = load_hardware_auth(vault_id)
        assert auth["failed_attempts"] == 1
        reset_failed_pin_attempts(vault_id)
        auth = load_hardware_auth(vault_id)
        assert auth["failed_attempts"] == 0
        testCount += 1
    except Exception as e:
        print(f"FAILED hardware auth: {e}")
        raise
    
    print("Vault data")
    try:
        data_id = save_vault_data(vault_id, "blob", "nonce")
        assert data_id > 0
        data = load_vault_data(vault_id)
        assert data["encrypted_blob"] == "blob"
        update_vault_data(vault_id, "new_blob", "new_nonce")
        data = load_vault_data(vault_id)
        assert data["encrypted_blob"] == "new_blob"
        testCount += 1
    except Exception as e:
        print(f"FAILED vault data: {e}")
        raise
        
    print("Access logs")
    try:
        log_id = write_access_log(vault_id, user_id, "LOGIN", "PASSPHRASE", True, "Success")
        assert log_id > 0
        testCount += 1
    except Exception as e:
        print(f"FAILED access logs: {e}")
        raise

    print(f"\nALL DATABASE TESTS PASSED! {testCount}/7")
    
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

if __name__ == "__main__":
    run_tests()
