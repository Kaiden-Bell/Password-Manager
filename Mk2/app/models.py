"""
app.models
──────────
SQLAlchemy ORM models for The Vault.

Tables
------
- User          — identity + passphrase verification metadata
- RFIDTag       — RFID UID + PIN verification metadata (linked to a user)
- AuditLog      — timestamped security events
- VaultMeta     — per-user vault references and wrapped master-key blobs
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    LargeBinary,
)
from sqlalchemy.orm import DeclarativeBase, relationship


# ── Base class ────────────────────────────────────

class Base(DeclarativeBase):
    """Shared declarative base for all models."""
    pass


# ── Models ────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    passphrase_hash = Column(LargeBinary, nullable=True)   # scrypt / PBKDF2 digest
    passphrase_salt = Column(LargeBinary, nullable=True)   # random salt
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    rfid_tags = relationship("RFIDTag", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    vault_meta = relationship("VaultMeta", back_populates="user", uselist=False, cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r}>"


class RFIDTag(Base):
    __tablename__ = "rfid_tags"

    id = Column(Integer, primary_key=True, autoincrement=True)
    uid_hex = Column(String(32), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    pin_hash = Column(LargeBinary, nullable=False)
    pin_salt = Column(LargeBinary, nullable=False)
    registered_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    user = relationship("User", back_populates="rfid_tags")

    def __repr__(self) -> str:
        return f"<RFIDTag id={self.id} uid={self.uid_hex!r} user_id={self.user_id}>"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    event = Column(String(128), nullable=False)
    detail = Column(Text, nullable=True)
    timestamp = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} event={self.event!r}>"


class VaultMeta(Base):
    __tablename__ = "vault_meta"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    vault_file = Column(String(256), nullable=False)            # relative path under vault_dir

    # Wrapped copies of the vault master key — one per auth path
    wrapped_key_rfid = Column(LargeBinary, nullable=True)       # wrapped with PIN-derived key
    wrapped_key_passphrase = Column(LargeBinary, nullable=True)  # wrapped with passphrase-derived key

    master_salt = Column(LargeBinary, nullable=False)            # shared KDF salt
    algorithm = Column(String(32), default="AES-256-GCM", nullable=False)

    # Relationships
    user = relationship("User", back_populates="vault_meta")

    def __repr__(self) -> str:
        return f"<VaultMeta id={self.id} user_id={self.user_id} file={self.vault_file!r}>"
