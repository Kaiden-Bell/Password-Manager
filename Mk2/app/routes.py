"""
routes.py — FastAPI API router.

All API endpoints are defined here and mounted on the /api prefix.
Each endpoint delegates to the appropriate module.
"""

from fastapi import APIRouter, HTTPException
import sqlite3

from app.models import (
    InitRequest,
    PassphraseUnlockRequest,
    SoftwareUnlockRequest,
    AddEntryRequest,
    UpdateEntryRequest,
    GeneratePasswordRequest,
    CheckPasswordRequest,
    MessageResponse,
    StatusResponse,
    EntryResponse,
    EntriesListResponse,
    GeneratePasswordResponse,
    CheckPasswordResponse,
    LogsResponse,
)

from app import auth, vault, session, password_utils, database, hardware

router = APIRouter(prefix="/api")

# -------------------------
# Initialization / Phases |
# -------------------------

@router.get("/vaults")
async def list_vaults(username: str | None = None):
    """
        Desc: Return vault names and IDs for a specific user (public, no session needed).
        Arguments: username
        Returns: dict, list of vaults
    """
    if not username:
        return {"vaults": []}
    try:
        vaults = database.get_user_vaults(username)
        for v in vaults:
            policy = database.load_vault_policy(v["vault_id"])
            v["hardware_gate_required"] = bool(policy.get("hardware_gate_required")) if policy else False
        return {"vaults": vaults}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/vaults/{vault_id}", response_model=MessageResponse)
async def delete_vault(vault_id: int):
    """
        Desc: Permanently delete a vault and all of its data. Requires an active unlocked session for the target vault.
        Arguments: vault_id
        Returns: MessageResponse
    """
    active_vault = session.get_active_vault_id()
    if active_vault is None or active_vault != vault_id:
        raise HTTPException(
            status_code=403,
            detail="You must unlock this vault before you can delete it."
        )

    try:
        session.lock_session(vault_id)
        database.delete_vault(vault_id)
        return MessageResponse(message=f"Vault {vault_id} deleted successfully")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/init", response_model=MessageResponse)
async def init_vault(request: InitRequest):
    """
        Desc: Initialize a new vault: user, policy, auth credentials, encrypted data.
        Arguments: username, vault_name, passphrase, keypad_pin, hardware_gate_required, software_only_enabled
        Returns: MessageResponse
    """
    try:
        result = auth.initialize_vault(
            username=request.username,
            vault_name=request.vault_name,
            passphrase=request.passphrase,
            keypad_pin=request.keypad_pin,
            hardware_gate_required=request.hardware_gate_required,
            software_only_enabled=request.software_only_enabled,
        )
        return MessageResponse(message=f"Vault {result['vault_id']} created successfully")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/unlock/passphrase", response_model=MessageResponse)
async def unlock_passphrase(request: PassphraseUnlockRequest):
    """
        Desc: Hardware-gated passphrase unlock.
        Arguments: vault_id, passphrase
        Returns: MessageResponse
    """
    if hardware.is_passphrase_locked_out(request.vault_id):
        session.close_passphrase_window(request.vault_id)
        hardware.send_locked()
        hardware.reset_passphrase_fails(request.vault_id)
        raise HTTPException(
            status_code=403,
            detail="Too many incorrect passphrase attempts. Please re-enter your PIN on the keypad."
        )

    try:
        auth.unlock_with_passphrase(request.vault_id, request.passphrase)
        hardware.reset_passphrase_fails(request.vault_id)
        hardware.send_granted()
        return MessageResponse(message=f"Vault {request.vault_id} unlocked successfully")
    except ValueError as e:
        fail_count = hardware.increment_passphrase_fail(request.vault_id)
        remaining = hardware.MAX_PASSPHRASE_ATTEMPTS - fail_count

        if hardware.is_passphrase_locked_out(request.vault_id):
            session.close_passphrase_window(request.vault_id)
            hardware.send_locked()
            hardware.reset_passphrase_fails(request.vault_id)
            raise HTTPException(
                status_code=403,
                detail="Too many incorrect passphrase attempts. Please re-enter your PIN on the keypad."
            )

        hardware.send_passphrase_fail()
        raise HTTPException(
            status_code=400,
            detail=f"Invalid passphrase. {remaining} attempt(s) remaining before PIN re-entry is required."
        )


@router.post("/unlock/software", response_model=MessageResponse)
async def unlock_software(request: SoftwareUnlockRequest):
    """
        Desc: Software-only passphrase unlock.
        Arguments: vault_id, passphrase
        Returns: MessageResponse
    """
    try:
        auth.unlock_software_only(request.vault_id, request.passphrase)
        return MessageResponse(message=f"Vault {request.vault_id} unlocked successfully")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/lock", response_model=MessageResponse)
async def lock_vault():
    """
        Desc: Lock the active vault session and clear all secrets.
        Arguments: None
        Returns: MessageResponse
    """
    vault_id = session.get_active_vault_id()
    if vault_id is None:
        raise HTTPException(status_code=400, detail="No active vault session found")
        
    session_data = session.get_session(vault_id)
    user_id = session_data.get('active_user_id') if session_data else None

    session.lock_session(vault_id)
    hardware.reset_passphrase_fails(vault_id)
    hardware.set_target_vault(None)
    hardware.send_locked()
    database.write_access_log(vault_id, user_id, "lock", None, True, "Vault locked")
    return MessageResponse(message=f"Vault {vault_id} locked successfully")

# -------------------------
# Hardware Vault Targeting |
# -------------------------

@router.put("/hardware/target", response_model=MessageResponse)
async def set_hardware_target(vault_id: int | None = None):
    """
        Desc: Tell the backend which vault the user has selected so the Arduino. PIN validation is tied to that specific vault.
        Arguments: vault_id (query param, optional — None clears the target)
        Returns: MessageResponse
    """
    hardware.set_target_vault(vault_id)
    if vault_id is not None:
        return MessageResponse(message=f"Hardware target set to vault {vault_id}")
    else:
        return MessageResponse(message="Hardware target cleared")

@router.get("/status", response_model=StatusResponse)
async def get_status(vault_id: int | None = None):
    """
        Desc: Return current vault lock state, hardware gate status, and passphrase window status.
        Arguments: vault_id
        Returns: StatusResponse
    """
    active_vault = session.get_active_vault_id()
    if not active_vault:
        window_active = False
        attempts_remaining = None
        if vault_id:
            window_active = session.is_passphrase_window_active(vault_id)
            if window_active:
                attempts_remaining = hardware.MAX_PASSPHRASE_ATTEMPTS - hardware.get_passphrase_fail_count(vault_id)
        return StatusResponse(
            is_locked=True,
            passphrase_window_active=window_active,
            passphrase_attempts_remaining=attempts_remaining,
            hardware_target_id=hardware.get_target_vault(),
        )
    
    is_locked = not session.is_unlocked(active_vault)
    session_data = session.get_session(active_vault)
    policy = database.load_vault_policy(active_vault) or {}
    
    pw_window_active = session.is_passphrase_window_active(active_vault)
    attempts_remaining = None
    if pw_window_active:
        attempts_remaining = hardware.MAX_PASSPHRASE_ATTEMPTS - hardware.get_passphrase_fail_count(active_vault)

    return StatusResponse(
        is_locked=is_locked,
        vault_id=active_vault,
        user_id=session_data['active_user_id'] if session_data else None,
        auth_method=session_data['auth_method'] if session_data else None,
        hardware_gate_required=bool(policy.get('hardware_gate_required', False)),
        software_only_enabled=bool(policy.get('software_only_enabled', True)),
        passphrase_window_active=pw_window_active,
        passphrase_window_seconds_remaining=session.get_passphrase_window_remaining(active_vault),
        passphrase_attempts_remaining=attempts_remaining,
        hardware_target_id=hardware.get_target_vault(),
    )

# --------------
# Entries CRUD |
# --------------

@router.get("/entries", response_model=EntriesListResponse)
async def list_entries():
    """
        Desc: Return all credential entries (requires unlocked session).
        Arguments: None
        Returns: EntriesListResponse
    """
    vault_id = session.get_active_vault_id()
    if vault_id is None:
        raise HTTPException(status_code=400, detail="No active vault session found")
    session_data = session.get_session(vault_id)
    if session_data is None:
        raise HTTPException(status_code=400, detail="No active vault session found")

    try:
        entries = session_data['decrypted_vault']['entries']
        return EntriesListResponse(entries=entries, count=len(entries))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/entries", response_model=EntryResponse)
async def add_entry(request: AddEntryRequest):
    """
        Desc: Add a new credential entry (requires unlocked session).
        Arguments: site, username, password
        Returns: EntryResponse
    """
    vault_id = session.get_active_vault_id()
    if vault_id is None:
        raise HTTPException(status_code=400, detail="No active vault session found")
    session_data = session.get_session(vault_id)
    if session_data is None:
        raise HTTPException(status_code=400, detail="No active vault session found")

    try:
        entry = vault.add_credential(
            vault_id,
            request.site,
            request.username,
            request.password
        )
        database.write_access_log(vault_id, session_data["active_user_id"], "add_credential", session_data["auth_method"], True, f"Added credential for {request.site}")
        return EntryResponse(**entry)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/entries/{entry_id}", response_model=EntryResponse)
async def update_entry(entry_id: int, request: UpdateEntryRequest):
    """
        Desc: Update an existing credential entry (requires unlocked session).
        Arguments: entry_id, site, username, password
        Returns: EntryResponse
    """
    vault_id = session.get_active_vault_id()
    if vault_id is None:
        raise HTTPException(status_code=400, detail="No active vault session found")
    session_data = session.get_session(vault_id)
    if session_data is None:
        raise HTTPException(status_code=400, detail="No active vault session found")

    try:
        entry = vault.update_credential(
            vault_id,
            entry_id,
            site=request.site,
            username=request.username,
            password=request.password
        )
        database.write_access_log(vault_id, session_data["active_user_id"], "update_credential", session_data["auth_method"], True, f"Updated credential ID {entry_id}")
        return EntryResponse(**entry)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/entries/{entry_id}", response_model=MessageResponse)
async def delete_entry(entry_id: int):
    """
        Desc: Delete a credential entry (requires unlocked session).
        Arguments: entry_id
        Returns: MessageResponse
    """
    vault_id = session.get_active_vault_id()
    if vault_id is None:
        raise HTTPException(status_code=400, detail="No active vault session found")
    session_data = session.get_session(vault_id)
    if session_data is None:
        raise HTTPException(status_code=400, detail="No active vault session found")

    try:
        vault.delete_credential(
            vault_id,
            entry_id
        )
        database.write_access_log(vault_id, session_data["active_user_id"], "delete_credential", session_data["auth_method"], True, f"Deleted credential ID {entry_id}")
        return MessageResponse(message=f"Entry {entry_id} deleted successfully")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/entries/search", response_model=EntriesListResponse)
async def search_entries(q: str = ""):
    """
        Desc: Search credential entries by site or username (requires unlocked session).
        Arguments: query
        Returns: EntriesListResponse
    """
    vault_id = session.get_active_vault_id()
    if vault_id is None:
        raise HTTPException(status_code=400, detail="No active vault session found")
    session_data = session.get_session(vault_id)
    if session_data is None:
        raise HTTPException(status_code=400, detail="No active vault session found")

    try:
        entries = vault.search_credentials(
            vault_id,
            q
        )
        return EntriesListResponse(entries=entries, count=len(entries))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# --------------------
# Password Utilities |
# --------------------

@router.post("/password/generate", response_model=GeneratePasswordResponse)
async def generate_password(request: GeneratePasswordRequest):
    """
        Desc: Generate a random password with specified options.
        Arguments: length, use_upper, use_lower, use_digits, use_symbols
        Returns: GeneratePasswordResponse
    """
    try:
        password = password_utils.generate_password(
            length=request.length,
            use_upper=request.use_upper,
            use_lower=request.use_lower,
            use_digits=request.use_digits,
            use_symbols=request.use_symbols
        )
        return GeneratePasswordResponse(password=password, length=len(password))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/password/check", response_model=CheckPasswordResponse)
async def check_password(request: CheckPasswordRequest):
    """
        Desc: Check the strength of a given password.
        Arguments: password
        Returns: CheckPasswordResponse
    """
    try:
        result = password_utils.check_password_strength(request.password)
        return CheckPasswordResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# -------------
# Access Logs |
# -------------

@router.get("/logs", response_model=LogsResponse)
async def get_logs():
    """
        Desc: Return access logs (requires unlocked session).
        Arguments: None
        Returns: LogsResponse
    """
    try:
        vault_id = session.get_active_vault_id()
        if vault_id is None:
            raise HTTPException(status_code=400, detail="No active vault session found")
        session_data = session.get_session(vault_id)
        if session_data is None:
            raise HTTPException(status_code=400, detail="No active vault session found")

        logs = database.get_access_logs(
            user_id=session_data['active_user_id'],
            vault_id=session_data['active_vault_id']
        )
        return LogsResponse(logs=logs, count=len(logs))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
