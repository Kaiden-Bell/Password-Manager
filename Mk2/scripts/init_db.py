"""
init_db.py — Initialize the SQLite database.

Creates all tables defined in the schema.
Run from project root:
    python scripts/init_db.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import initialize_database
from app.config import DATABASE_PATH


def main():
    print(f"Initializing database at: {DATABASE_PATH}")
    initialize_database()
    print("Database initialized successfully.")
    print(f"Tables created in: {DATABASE_PATH}")


if __name__ == "__main__":
    main()
