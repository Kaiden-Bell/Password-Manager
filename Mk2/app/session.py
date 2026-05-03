"""
session.py — In-memory session manager.

Tracks vault unlock state, decrypted data, and passphrase windows.
All secrets are held only in memory and cleared on lock.
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
        Desc: Check if a vault has an active, unlocked session.
        Args: vault_id: The ID of the vault to check.
        Return: bool: True if the vault has an active, unlocked session, False otherwise.
    """
    session = _sessions.get(vault_id)
    if not session: return False
    return session.get('is_unlocked') and time.time() - session.get('last_activity') < SESSION_TIMEOUT_SECONDS

def get_session(vault_id: int) -> dict | None:
    """
        Desc: Retrieve the session dict for a vault, or None if not found.
        Args: vault_id: The ID of the vault to retrieve the session for.
        Return: dict | None: The session dict for the vault, or None if the vault is not found.
    """
    session = _sessions.get(vault_id)
    
    return session if is_unlocked(vault_id) else None

def get_active_vault_id() -> int | None:
    """
        Desc: Return the vault_id of the currently active (unlocked) session.
        Args: None
        Return: int | None: The vault_id of the currently active (unlocked) session, or None if no session is active.
    """
    for vault_id in _sessions:
        if is_unlocked(vault_id):
            return vault_id
    return None

def touch_session(vault_id: int) -> None:
    """
        Desc: Update last_activity timestamp to prevent session timeout.
        Args: vault_id: The ID of the vault to touch.
        Return: None
    """
    session = _sessions.get(vault_id)

    if session and is_unlocked(vault_id):
        session['last_activity'] = time.time()
    else:
        pass

def lock_session(vault_id: int) -> None:
    """
        Desc: Lock a vault session and clear all secrets from memory.
        Args: vault_id: The ID of the vault to lock.
        Return: None
    """
    session = _sessions.get(vault_id)

    if session and is_unlocked(vault_id):
        clear_secrets(vault_id)
        del _sessions[vault_id]
    else:
        pass

def expire_old_sessions() -> list[int]:
    """ 
        Desc: Find and lock sessions that have exceeded SESSION_TIMEOUT_SECONDS.
        Args: None
        Return: list[int]: A list of vault_ids that were expired.
    """
    expired_sessions = []

    for vault_id, session in _sessions.items():
        if time.time() - session.get('last_activity') > SESSION_TIMEOUT_SECONDS:
            lock_session(vault_id)
            expired_sessions.append(vault_id)

    return expired_sessions


def clear_secrets(vault_id: int) -> None:
    """
        Desc: Securely clear decrypted vault data and master key from a session.
        Args: vault_id: The ID of the vault to clear secrets from.
        Return: None
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
        Desc: Open a temporary passphrase-entry window for a vault.
        Args: 
            vault_id: The ID of the vault to open the window for.
            seconds: The number of seconds to keep the window open.
        Return: float: The expiry time of the window.
    """
    expiry = time.time() + seconds
    _passphrase_windows[vault_id] = expiry
    return expiry

def is_passphrase_window_active(vault_id: int) -> bool:
    """
        Desc: Check whether the passphrase window is still open.
        Args: vault_id: The ID of the vault to check.
        Return: bool: True if the passphrase window is active, False otherwise.
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
        Desc: Close the passphrase window for a vault.
        Args: vault_id: The ID of the vault to close the window for.
        Return: None
    """
    if vault_id in _passphrase_windows:
        del _passphrase_windows[vault_id]

def get_passphrase_window_remaining(vault_id: int) -> float:
    """
        Desc: Get the remaining seconds of the passphrase window.
        Args: vault_id: The ID of the vault to get the remaining seconds for.
        Return: float: The remaining seconds of the passphrase window.
    """
    if not is_passphrase_window_active(vault_id):
        return 0.0
    return max(0.0, _passphrase_windows[vault_id] - time.time())

