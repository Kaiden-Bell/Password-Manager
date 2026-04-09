"""
app.config
──────────
Centralised configuration loaded from environment variables / .env file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


# Load .env from project root (two levels up from this file)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class Config:
    """Immutable application configuration."""

    # ── Serial / Arduino ─────────────────────────
    serial_port: str = "/dev/ttyUSB0"
    serial_baud: int = 115200

    # ── Database ─────────────────────────────────
    database_url: str = f"sqlite:///{_PROJECT_ROOT / 'data' / 'thevault.db'}"

    # ── Vault ────────────────────────────────────
    vault_dir: str = str(_PROJECT_ROOT / "data" / "vaults")

    # ── Flask ────────────────────────────────────
    secret_key: str = "change-me-to-a-random-secret"
    debug: bool = True

    # ── Crypto ───────────────────────────────────
    kdf_iterations: int = 600_000  # PBKDF2 iterations

    # ──────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> Config:
        """Build a Config from current environment variables."""
        return cls(
            serial_port=os.getenv("SERIAL_PORT", cls.serial_port),
            serial_baud=int(os.getenv("SERIAL_BAUD", str(cls.serial_baud))),
            database_url=os.getenv("DATABASE_URL", cls.database_url),
            vault_dir=os.getenv("VAULT_DIR", cls.vault_dir),
            secret_key=os.getenv("SECRET_KEY", cls.secret_key),
            debug=os.getenv("FLASK_DEBUG", "1") == "1",
            kdf_iterations=int(
                os.getenv("KDF_ITERATIONS", str(cls.kdf_iterations))
            ),
        )
