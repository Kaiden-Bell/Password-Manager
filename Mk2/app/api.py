"""
app.api
───────
Flask blueprint exposing REST endpoints for The Vault.

Endpoints
---------
POST /api/auth/rfid          — authenticate via RFID UID + PIN
POST /api/auth/passphrase    — authenticate via username + passphrase
GET  /api/vault              — retrieve decrypted vault (session required)
POST /api/vault/credential   — add a credential (session required)
GET  /api/status             — health / serial-bridge status
"""

from __future__ import annotations

import secrets
from functools import wraps
from typing import Callable

from flask import Blueprint, current_app, jsonify, request, session

from app.auth import AuthError, authenticate_passphrase, authenticate_rfid_pin
from app.config import Config
from app.database import get_db
from app.vault import add_credential, read_vault

api_bp = Blueprint("api", __name__)


# ── In-memory session store (simple token → master_key) ──

_sessions: dict[str, dict] = {}
# Format:  { token: {"user_id": int, "username": str, "master_key": bytes} }


def _get_config() -> Config:
    return current_app.config["VAULT_CONFIG"]


# ── Auth helpers ──────────────────────────────────

def _create_token(user_id: int, username: str, master_key: bytes) -> str:
    """Generate a random session token and store it in memory."""
    token = secrets.token_hex(32)
    _sessions[token] = {
        "user_id": user_id,
        "username": username,
        "master_key": master_key,
    }
    return token


def require_auth(fn: Callable) -> Callable:
    """Decorator that verifies the ``Authorization: Bearer <token>`` header."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header."}), 401

        token = auth_header[7:]
        session_data = _sessions.get(token)
        if session_data is None:
            return jsonify({"error": "Invalid or expired token."}), 401

        # Attach session data to Flask's ``g`` alternative via kwargs
        kwargs["session_data"] = session_data
        return fn(*args, **kwargs)
    return wrapper


# ── Auth Endpoints ────────────────────────────────

@api_bp.route("/auth/rfid", methods=["POST"])
def auth_rfid():
    """Authenticate with RFID UID + PIN."""
    body = request.get_json(silent=True) or {}
    uid = body.get("uid", "").strip()
    pin = body.get("pin", "").strip()

    if not uid or not pin:
        return jsonify({"error": "Both 'uid' and 'pin' are required."}), 400

    cfg = _get_config()
    try:
        with get_db() as db:
            user, master_key = authenticate_rfid_pin(
                uid, pin, db, cfg.kdf_iterations
            )
            token = _create_token(user.id, user.username, master_key)
    except AuthError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({"token": token, "username": user.username}), 200


@api_bp.route("/auth/passphrase", methods=["POST"])
def auth_passphrase():
    """Authenticate with username + passphrase."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "").strip()
    passphrase = body.get("passphrase", "").strip()

    if not username or not passphrase:
        return jsonify({"error": "Both 'username' and 'passphrase' are required."}), 400

    cfg = _get_config()
    try:
        with get_db() as db:
            user, master_key = authenticate_passphrase(
                username, passphrase, db, cfg.kdf_iterations
            )
            token = _create_token(user.id, user.username, master_key)
    except AuthError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({"token": token, "username": user.username}), 200


# ── Vault Endpoints ───────────────────────────────

@api_bp.route("/vault", methods=["GET"])
@require_auth
def get_vault(session_data: dict):
    """Return the decrypted vault contents."""
    cfg = _get_config()
    vault_filename = f"{session_data['user_id']}.vault"
    try:
        data = read_vault(cfg.vault_dir, vault_filename, session_data["master_key"])
    except FileNotFoundError:
        return jsonify({"error": "Vault file not found."}), 404
    except Exception as exc:
        return jsonify({"error": f"Failed to decrypt vault: {exc}"}), 500

    return jsonify(data), 200


@api_bp.route("/vault/credential", methods=["POST"])
@require_auth
def post_credential(session_data: dict):
    """Add a credential to the vault."""
    body = request.get_json(silent=True) or {}
    service = body.get("service", "").strip()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()

    if not service or not username or not password:
        return jsonify({"error": "'service', 'username', and 'password' are required."}), 400

    cfg = _get_config()
    vault_filename = f"{session_data['user_id']}.vault"
    try:
        data = add_credential(
            cfg.vault_dir,
            vault_filename,
            session_data["master_key"],
            service,
            username,
            password,
        )
    except FileNotFoundError:
        return jsonify({"error": "Vault file not found."}), 404
    except Exception as exc:
        return jsonify({"error": f"Failed to update vault: {exc}"}), 500

    return jsonify({"message": "Credential added.", "vault": data}), 201


# ── Status ────────────────────────────────────────

@api_bp.route("/status", methods=["GET"])
def status():
    """Health check."""
    return jsonify({
        "status": "ok",
        "active_sessions": len(_sessions),
    }), 200
