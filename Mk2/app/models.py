"""
models.py — Pydantic v2 request/response models for the API.

Defines the frontend <--> backend contract.
"""

from pydantic import BaseModel, Field

# ----------------
# Request Models |
# ----------------

class InitRequest(BaseModel):
    """POST /api/init — Initialize a new vault."""
    username: str
    display_name: str
    vault_name: str
    passphrase: str
    keypad_pin: str | None = None
    hardware_gate_required: bool = False
    software_only_enabled: bool = True

class PassphraseUnlockRequest(BaseModel):
    """POST /api/unlock/passphrase — Hardware-gated unlock."""
    vault_id: int
    passphrase: str

class SoftwareUnlockRequest(BaseModel):
    """POST /api/unlock/software — Software-only unlock."""
    vault_id: int
    passphrase: str

class AddEntryRequest(BaseModel):
    """POST /api/entries — Add a new credential."""
    site: str
    username: str
    password: str

class UpdateEntryRequest(BaseModel):
    """PUT /api/entries/{entry_id} — Update a credential."""
    site: str | None = None
    username: str | None = None
    password: str | None = None

class GeneratePasswordRequest(BaseModel):
    """POST /api/password/generate — Generate a random password."""
    length: int = Field(default=16, ge=8, le=128)
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True

class CheckPasswordRequest(BaseModel):
    """POST /api/password/check — Check password strength."""
    password: str

# -----------------
# Response Models |
# -----------------

class MessageResponse(BaseModel):
    """Generic success/error message."""
    message: str
    success: bool = True

class StatusResponse(BaseModel):
    """GET /api/status — Current vault status."""
    is_locked: bool
    vault_id: int | None = None
    user_id: int | None = None
    auth_method: str | None = None
    hardware_gate_required: bool = False
    software_only_enabled: bool = True
    passphrase_window_active: bool = False
    passphrase_window_seconds_remaining: float = 0.0

class EntryResponse(BaseModel):
    """Single credential entry."""
    entry_id: int
    site: str
    username: str
    password: str
    last_rotated: str

class EntriesListResponse(BaseModel):
    """GET /api/entries — List of credential entries."""
    entries: list[EntryResponse]
    count: int

class GeneratePasswordResponse(BaseModel):
    """POST /api/password/generate — Generated password result."""
    password: str
    length: int

class CheckPasswordResponse(BaseModel):
    """POST /api/password/check — Password strength result."""
    score: int = Field(ge=0, le=4, description="0=very weak, 4=very strong")
    label: str
    feedback: list[str]

class LogEntry(BaseModel):
    """Single access log entry."""
    log_id: int
    vault_id: int | None
    user_id: int | None
    event_type: str
    auth_method: str | None
    success: bool
    details: str | None
    timestamp: str

class LogsResponse(BaseModel):
    """GET /api/logs — Access log listing."""
    logs: list[LogEntry]
    count: int
