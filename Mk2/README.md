# The Vault

A local encrypted password manager with optional Arduino keypad-based hardware gating.

## Overview

The Vault stores credentials locally in an encrypted PostgreSQL database. It uses two unlock modes to balance security with convenience.

### Hardware-Gated Mode
1. Enter a 6-digit PIN on an Arduino-connected keypad.
2. Arduino sends the PIN attempt to the Python backend over serial.
3. Backend validates the PIN hash against the database.
4. If valid, a temporary passphrase-entry window opens (30–60 seconds).
5. Enter the passphrase in the Web UI.
6. Backend derives a wrapping key (Argon2id), unwraps the vault master key, and decrypts the vault data.
7. Arduino green LED turns on.

### Software-Only Mode
1. Select software-only unlock in the Web UI.
2. Enter the passphrase.
3. Backend verifies vault policy allows software-only mode.
4. Backend derives the wrapping key, unwraps the vault master key, and decrypts the vault data.

> **Note:** The keypad PIN does NOT decrypt the vault. It only opens a temporary passphrase window. The passphrase is the sole cryptographic unlock factor.

## Security Model

```
Passphrase  →  Argon2id  →  wrapping key
wrapping key  →  unwrap vault master key
vault master key  →  decrypt encrypted vault data
```

### Key Security Rules
- Raw passphrases are **never** stored.
- Raw keypad PINs are **never** stored.
- Plaintext passwords are **never** stored in the database.
- Decrypted vault data only exists in backend memory while unlocked.
- Locking the vault clears all secrets from memory.
- Software-only mode must be explicitly allowed by vault policy.
- The Python backend is the **sole trust authority**.
- The Arduino handles keypad input and LEDs only.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, FastAPI, Uvicorn |
| Database | PostgreSQL (psycopg2-binary) |
| Crypto | argon2-cffi, PyNaCl (XChaCha20-Poly1305) |
| Frontend | HTML, CSS, vanilla JavaScript |
| Hardware | Arduino Mega, 4×4 keypad, LEDs |
| Serial | pyserial |

## Folder Structure

```
the_vault/
├── app/
│   ├── __init__.py          # Package marker
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Configuration constants
│   ├── models.py            # Pydantic request/response models
│   ├── database.py          # PostgreSQL OOP wrapper + schema
│   ├── auth.py              # Authentication orchestration
│   ├── crypto.py            # Cryptographic operations
│   ├── vault.py             # Vault data operations
│   ├── password_utils.py    # Password generation/strength
│   ├── serial_service.py    # Raw serial communication
│   ├── hardware.py          # Hardware auth logic
│   ├── session.py           # In-memory session manager
│   └── routes.py            # FastAPI API routes

├── frontend/
│   ├── index.html           # Single-page UI
│   ├── style.css            # Dark theme styles
│   └── app.js               # Frontend logic
├── arduino/
│   └── keypad_controller.ino # Arduino sketch
├── scripts/
│   ├── init_db.py           # Database initialization
│   └── seed_demo.py         # Demo data seeder
├── tests/
│   ├── test_crypto.py       # Crypto tests
│   ├── test_auth.py         # Auth tests
│   ├── test_vault.py        # Vault tests
│   └── test_database.py     # Database tests
├── requirements.txt
└── README.md
```

## Database Schema

8 tables: `users`, `vaults`, `vault_policy`, `auth_credentials`, `hardware_auth`, `hardware_devices`, `vault_data`, `access_logs`.

Full DDL is in `app/database.py`.

## Setup

### Prerequisites
- Python 3.11+
- PostgreSQL server running (with credentials matching app/config.py)
- (Optional) Arduino Mega with 4×4 keypad and 3 LEDs

### Installation

```bash
cd the_vault
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

### Initialize the Database

```bash
python scripts/init_db.py
```

### Run the Backend

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Open the Frontend

Navigate to `http://127.0.0.1:8000` in your browser.

### Arduino Setup

1. Open `arduino/keypad_controller.ino` in the Arduino IDE.
2. Update pin assignments in the sketch for your wiring.
3. Upload to the Arduino Mega.
4. Update `SERIAL_PORT` in `app/config.py` to match your Arduino port.

## API Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/init` | Initialize vault |
| POST | `/api/unlock/passphrase` | Hardware-gated unlock |
| POST | `/api/unlock/software` | Software-only unlock |
| POST | `/api/lock` | Lock vault |
| GET | `/api/status` | Vault status |
| GET | `/api/entries` | List credentials |
| POST | `/api/entries` | Add credential |
| PUT | `/api/entries/{id}` | Update credential |
| DELETE | `/api/entries/{id}` | Delete credential |
| GET | `/api/entries/search?q=` | Search credentials |
| POST | `/api/password/generate` | Generate password |
| POST | `/api/password/check` | Check password strength |
| GET | `/api/logs` | Access logs |

## Future Improvements

- Multi-vault support
- Credential categories and tags
- Export/import functionality
- Biometric unlock option
- Rate limiting on PIN attempts
- Encrypted database backups
- Browser extension integration
- TOTP/2FA storage
