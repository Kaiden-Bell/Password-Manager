"""
app.auth
────────
Authentication logic for The Vault.

Two independent paths lead to the same result — an unwrapped vault master key:

1. RFID + PIN    →  look up RFIDTag by UID, verify PIN, unwrap via wrapped_key_rfid
2. Username + Passphrase  →  look up User, verify passphrase, unwrap via wrapped_key_passphrase
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.crypto import derive_key, unwrap_key
from app.models import AuditLog, RFIDTag, User, VaultMeta


class AuthError(Exception):
    """Raised when authentication fails."""
    pass


# ── Low-level verification ────────────────────────

def verify_pin(tag: RFIDTag, pin: str, iterations: int = 600_000) -> bool:
    """Return True if *pin* matches the stored hash on *tag*."""
    derived = derive_key(pin, tag.pin_salt, iterations)
    return derived == tag.pin_hash


def verify_passphrase(user: User, passphrase: str, iterations: int = 600_000) -> bool:
    """Return True if *passphrase* matches the stored hash on *user*."""
    if user.passphrase_hash is None or user.passphrase_salt is None:
        return False
    derived = derive_key(passphrase, user.passphrase_salt, iterations)
    return derived == user.passphrase_hash


# ── High-level auth flows ─────────────────────────

def authenticate_rfid_pin(
    uid_hex: str,
    pin: str,
    session: Session,
    iterations: int = 600_000,
) -> tuple[User, bytes]:
    """
    Authenticate via RFID UID + PIN.

    Returns ``(user, master_key)`` on success.
    Raises ``AuthError`` on failure.
    """
    tag = session.query(RFIDTag).filter_by(uid_hex=uid_hex.upper()).first()
    if tag is None:
        _log_event(session, None, "AUTH_RFID_FAIL", f"Unknown UID {uid_hex}")
        raise AuthError("RFID tag not registered.")

    if not verify_pin(tag, pin, iterations):
        _log_event(session, tag.user_id, "AUTH_PIN_FAIL", f"Bad PIN for UID {uid_hex}")
        raise AuthError("Invalid PIN.")

    user = tag.user
    vault_meta: VaultMeta | None = user.vault_meta
    if vault_meta is None or vault_meta.wrapped_key_rfid is None:
        raise AuthError("No vault configured for this user (RFID path).")

    # Derive wrapping key from PIN + master_salt, then unwrap
    wrapping_key = derive_key(pin, vault_meta.master_salt, iterations)
    try:
        master_key = unwrap_key(vault_meta.wrapped_key_rfid, wrapping_key)
    except Exception as exc:
        _log_event(session, user.id, "AUTH_UNWRAP_FAIL", str(exc))
        raise AuthError("Failed to unwrap vault key.") from exc

    _log_event(session, user.id, "AUTH_RFID_OK", f"UID {uid_hex}")
    return user, master_key


def authenticate_passphrase(
    username: str,
    passphrase: str,
    session: Session,
    iterations: int = 600_000,
) -> tuple[User, bytes]:
    """
    Authenticate via username + passphrase (fallback / recovery path).

    Returns ``(user, master_key)`` on success.
    Raises ``AuthError`` on failure.
    """
    user = session.query(User).filter_by(username=username).first()
    if user is None:
        _log_event(session, None, "AUTH_PASS_FAIL", f"Unknown user {username!r}")
        raise AuthError("User not found.")

    if not verify_passphrase(user, passphrase, iterations):
        _log_event(session, user.id, "AUTH_PASS_FAIL", "Bad passphrase")
        raise AuthError("Invalid passphrase.")

    vault_meta: VaultMeta | None = user.vault_meta
    if vault_meta is None or vault_meta.wrapped_key_passphrase is None:
        raise AuthError("No vault configured for this user (passphrase path).")

    wrapping_key = derive_key(passphrase, vault_meta.master_salt, iterations)
    try:
        master_key = unwrap_key(vault_meta.wrapped_key_passphrase, wrapping_key)
    except Exception as exc:
        _log_event(session, user.id, "AUTH_UNWRAP_FAIL", str(exc))
        raise AuthError("Failed to unwrap vault key.") from exc

    _log_event(session, user.id, "AUTH_PASS_OK", f"User {username!r}")
    return user, master_key


# ── Helpers ────────────────────────────────────────

def _log_event(
    session: Session,
    user_id: int | None,
    event: str,
    detail: str = "",
) -> None:
    """Insert an audit-log row (best-effort, won't raise)."""
    try:
        session.add(AuditLog(user_id=user_id, event=event, detail=detail))
        session.flush()
    except Exception:
        pass  # logging failures must never block auth
