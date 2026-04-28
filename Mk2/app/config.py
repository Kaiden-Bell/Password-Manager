"""
config.py — Application configuration constants.

All configuration values are module-level variables.
Adjust these as needed for your environment.
"""

import os

# # -------------
# Paths
# # -------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "data", "vault.db")

# # -------------
# Serial / Arduino
# # -------------
SERIAL_PORT = "/dev/ttyACM0"   # Update for your OS (e.g., "COM3" on Windows)
BAUD_RATE = 9600

# # -------------
# Hardware Gate
# # -------------
GATE_WINDOW_SECONDS = 60       # Seconds the passphrase window stays open

# # -------------
# Session
# # -------------
SESSION_TIMEOUT_SECONDS = 5  # Auto-lock after 5 minutes of inactivity

# # -------------
# Argon2id KDF Parameters
# # -------------
ARGON2_MEMORY_COST = 65536     # 64 MiB
ARGON2_TIME_COST = 3           # iterations
ARGON2_PARALLELISM = 4         # threads
KEY_LENGTH = 32                # 256-bit key
