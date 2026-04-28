"""
session.py — In-memory session manager.

Tracks vault unlock state, decrypted data, and passphrase windows.
All secrets are held only in memory and cleared on lock.

Security Notes:
    - Decrypted vault data and master key exist ONLY in session memory.
    - Locking a session MUST zero out secrets.
    - Sessions auto-expire after SESSION_TIMEOUT_SECONDS of inactivity.
"""

import time
from app.config import SESSION_TIMEOUT_SECONDS, GATE_WINDOW_SECONDS


# -----------------
# Session Storage |
# -----------------

# In-memory session store: vault_id -> session dict
_sessions: dict[int, dict] = {}

# In-memory passphrase window store: vault_id -> expiry timestamp
_passphrase_windows: dict[int, float] = {}


# -------------------
# Session Lifecycle |
# -------------------

def create_session(
    user_id: int,
    vault_id: int,
    auth_method: str,
    decrypted_vault: dict,
    master_key: bytes,
) -> dict:
    """
    Create a new unlocked session for a vault.
    """

    # Init values
    is_unlocked = True
    active_user_id = user_id
    active_vault_id = vault_id
    vault_master_key = master_key
    last_activity = time.time()

    session = {
        "is_unlocked": is_unlocked,
        "active_user_id": active_user_id,
        "active_vault_id": active_vault_id,
        "auth_method": auth_method,
        "decrypted_vault": decrypted_vault,
        "vault_master_key": vault_master_key,
        "last_activity": last_activity,
    }

    _sessions[vault_id] = session
    return session
    
def is_unlocked(vault_id: int) -> bool:
    """
    Check if a vault has an active, unlocked session.
    """
    session = _sessions.get(vault_id)

    if not session:
        return False

    if session.get('is_unlocked') and time.time() - session.get('last_activity') < SESSION_TIMEOUT_SECONDS:
        return True
    else:
        return False        

def get_session(vault_id: int) -> dict | None:
    """
    Retrieve the session dict for a vault, or None if not found.
    """
    session = _sessions.get(vault_id)
    
    return session if is_unlocked(vault_id) else None

def touch_session(vault_id: int) -> None:
    """
    Update last_activity timestamp to prevent session timeout.
    """

    session = _sessions.get(vault_id)

    if session and is_unlocked(vault_id):
        session['last_activity'] = time.time()
    else:
        pass

def lock_session(vault_id: int) -> None:
    """
    Lock a vault session and clear all secrets from memory.
    """

    session = _sessions.get(vault_id)

    if session and is_unlocked(vault_id):
        clear_secrets(vault_id)
        del _sessions[vault_id]
    else:
        pass

def expire_old_sessions() -> list[int]:
    """
    Find and lock sessions that have exceeded SESSION_TIMEOUT_SECONDS.
    """

    expired_sessions = []

    for vault_id, session in _sessions.items():
        if time.time() - session.get('last_activity') > SESSION_TIMEOUT_SECONDS:
            lock_session(vault_id)
            expired_sessions.append(vault_id)

    return expired_sessions


def clear_secrets(vault_id: int) -> None:
    """
    Securely clear decrypted vault data and master key from a session.
    """

    session = _sessions.get(vault_id)

    if session:
        session['decrypted_vault'] = None
        session['vault_master_key'] = None
        session['is_unlocked'] = False

# -------------------
# Passphrase Window |
# -------------------

def open_passphrase_window(
    vault_id: int,
    seconds: int = GATE_WINDOW_SECONDS,
) -> float:
    """
    Open a temporary passphrase-entry window for a vault.
    """

    expiry = time.time() + seconds
    _passphrase_windows[vault_id] = expiry
    return expiry

def is_passphrase_window_active(vault_id: int) -> bool:
    """
    Check whether the passphrase window is still open.
    """

    if vault_id not in _passphrase_windows:
        return False

    if time.time() > _passphrase_windows[vault_id]:
        del _passphrase_windows[vault_id]
        return False
    else:
        return True

def close_passphrase_window(vault_id: int) -> None:
    """
    Close the passphrase window for a vault.
    """

    if vault_id in _passphrase_windows:
        del _passphrase_windows[vault_id]
