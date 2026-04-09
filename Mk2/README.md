# The Vault

A local secure credential vault with hardware-assisted RFID + PIN authentication and a username + passphrase fallback path.

## Architecture

```
┌──────────────┐     Serial     ┌─────────────────┐     SQLite      ┌───────────┐
│   Arduino    │ ──────────────▶│  Python Backend  │ ──────────────▶ │  Database  │
│  RFID Reader │   (115200 bd)  │   (Flask API)    │                 │  (SQLAlchemy)
└──────────────┘                └────────┬─────────┘                 └───────────┘
                                         │
                                    AES-256-GCM
                                         │
                                    ┌────▼────┐
                                    │  Vault  │
                                    │  Files  │
                                    └─────────┘
```

## Auth Flows

| Path | Input | Key Derivation | Unlocks |
|------|-------|----------------|---------|
| **RFID + PIN** | UID from scanner + numeric PIN | PBKDF2(PIN, salt) → wrapping key | `wrapped_key_rfid` → master key |
| **Passphrase** | username + passphrase | PBKDF2(passphrase, salt) → wrapping key | `wrapped_key_passphrase` → master key |

Both paths unwrap the **same** vault master key, which decrypts the credential vault.

## Project Structure

```
Mk2/
├── app/
│   ├── __init__.py        # Flask app factory
│   ├── api.py             # REST endpoints
│   ├── auth.py            # Authentication logic
│   ├── config.py          # .env config loader
│   ├── crypto.py          # AES-GCM, PBKDF2, key wrapping
│   ├── database.py        # SQLAlchemy engine/session
│   ├── models.py          # ORM models
│   ├── serial_bridge.py   # Arduino serial listener
│   └── vault.py           # Encrypted vault file I/O
├── arduino/
│   └── rfid_scanner.ino   # MFRC522 RFID scanner sketch
├── data/                  # SQLite DB + vault files (gitignored)
├── scripts/
│   ├── init_db.py         # Database bootstrap
│   └── register_user.py   # User enrollment CLI
├── frontend/              # (future) web UI
├── tests/                 # (future) test suite
├── .env.example           # Environment config template
├── requirements.txt       # Python dependencies
└── README.md
```

## Quickstart

```bash
# 1. Create and activate a virtualenv
python -m venv .venv && source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy env template and edit as needed
cp .env.example .env

# 4. Initialise the database
python scripts/init_db.py

# 5. Register a user
python scripts/register_user.py

# 6. Run the Flask API
flask --app app run --debug
```

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/auth/rfid` | POST | Authenticate with `{uid, pin}` |
| `/api/auth/passphrase` | POST | Authenticate with `{username, passphrase}` |
| `/api/vault` | GET | Retrieve decrypted vault (Bearer token required) |
| `/api/vault/credential` | POST | Add a credential to the vault |
| `/api/status` | GET | Health check |
