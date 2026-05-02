"""
routes.py — FastAPI API router.

All API endpoints are defined here and mounted on the /api prefix.
Each endpoint delegates to the appropriate module.
"""

from fastapi import APIRouter, HTTPException

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

@router.post("/init", response_model=MessageResponse)
async def init_vault(request: InitRequest):
    """
        Desc: Initialize a new vault: user, policy, auth credentials, encrypted data.
        Arguments: username, display_name, vault_name, passphrase, keypad_pin, hardware_gate_required, software_only_enabled
        Returns: dict, vault id and success status
    """
    try:
        vault_id = auth.initialize_vault(
            request.username,
            request.display_name,
            request.passphrase,
            request.hardware_pin,
            request.policy,
        )
        return MessageResponse(message=f"Vault {vault_id} created successfully")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/unlock/passphrase", response_model=MessageResponse)
async def unlock_passphrase(request: PassphraseUnlockRequest):
    """
        Desc: Hardware-gated passphrase unlock.
        Arguments: vault_id, passphrase, auth_method
        Returns: dict, session data and vault id
    """
    try:
        auth.unlock_with_passphrase(request.vault_id, request.passphrase)
        return MessageResponse(message=f"Vault {request.vault_id} unlocked successfully")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/unlock/software", response_model=MessageResponse)
async def unlock_software(request: SoftwareUnlockRequest):
    """
        Desc: Software-only passphrase unlock.
        Arguments: vault_id, passphrase, auth_method
        Returns: dict, session data and vault id
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
        Arguments: vault_id
        Returns: dict, session data and vault id
    """
    vault_id = session.get_active_vault_id()
    if vault_id is None:
        raise HTTPException(status_code=400, detail="No active vault session found")
        
    session_data = session.get_session(vault_id)
    user_id = session_data.get('active_user_id') if session_data else None

    session.lock_session(vault_id)
    hardware.send_locked()
    database.write_access_log(vault_id, user_id, "lock", None, True, "Vault locked")
    return MessageResponse(message=f"Vault {vault_id} locked successfully")

@router.get("/status", response_model=StatusResponse)
async def get_status():
    """
        Desc: Return current vault lock state, hardware gate status,
        and passphrase window status.
        Arguments: vault_id
        Returns: StatusResponse
    """
    vault_id = session.get_active_vault_id()
    if not vault_id:
        return StatusResponse(is_locked=True)
        
    is_locked = not session.is_unlocked(vault_id)
    session_data = session.get_session(vault_id)
    policy = database.load_vault_policy(vault_id) or {}
    
    return StatusResponse(
        is_locked=is_locked,
        vault_id=vault_id,
        user_id=session_data['active_user_id'] if session_data else None,
        auth_method=session_data['auth_method'] if session_data else None,
        hardware_gate_required=bool(policy.get('hardware_gate_required', False)),
        software_only_enabled=bool(policy.get('software_only_enabled', True)),
        passphrase_window_active=session.is_passphrase_window_active(vault_id),
        passphrase_window_seconds_remaining=session.get_passphrase_window_remaining(vault_id)
    )

# --------------
# Entries CRUD |
# --------------

@router.get("/entries", response_model=EntriesListResponse)
async def list_entries():
    """
        Desc: Return all credential entries (requires unlocked session).
        Arguments: vault_id
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
        Arguments: vault_id, site, username, password
        Returns: dict, session data and vault id
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
        Arguments: vault_id, entry_id, site, username, password
        Returns: dict, session data and vault id
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
        Arguments: vault_id, entry_id
        Returns: dict, session data and vault id
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
        Arguments: vault_id, query
        Returns: dict, session data and vault id
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
        Arguments: vault_id, site, username, password
        Returns: dict, session data and vault id
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
        Arguments: vault_id, site, username, password
        Returns: dict, session data and vault id
    """
    try:
        result = password_utils.check_password_strength(request.password)
        return CheckPasswordResponse(result=result)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# -------------
# Access Logs |
# -------------

@router.get("/logs", response_model=LogsResponse)
async def get_logs():
    """
        Desc: Return access logs (requires unlocked session).
        Arguments: vault_id, user_id
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
