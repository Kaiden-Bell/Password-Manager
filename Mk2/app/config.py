"""
config.py — Application configuration constants.

All configuration values are module-level variables.
Adjust these as needed for your environment.
"""

import os
import platform

# -------
# Paths |
# -------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/vault_db"
# ------------------
# Serial / Arduino |
# ------------------

if platform.system() == "Windows":
    SERIAL_PORT = "COM5"  # Or "COM3", "COM4", etc.
else:
    # macOS / Linux
    SERIAL_PORT = "/dev/ttyACM0"  # Or "/dev/tty.usbmodem..."

BAUD_RATE = 9600

# ---------------
# Hardware Gate |
# ---------------
GATE_WINDOW_SECONDS = 60       # Seconds the passphrase window stays open

# -----------------
# Session Timeout |
# -----------------
SESSION_TIMEOUT_SECONDS = 300  # Auto-lock after 5 minutes of inactivity

# -------------------------
# Argon2id KDF Parameters |
# -------------------------
ARGON2_MEMORY_COST = 65536     # 64 MiB
ARGON2_TIME_COST = 3           # iterations
ARGON2_PARALLELISM = 4         # threads
KEY_LENGTH = 32                # 256-bit key
