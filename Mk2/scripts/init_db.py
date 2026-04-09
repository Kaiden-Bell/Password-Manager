#!/usr/bin/env python3
"""
scripts/init_db.py
──────────────────
Bootstrap the SQLite database — creates all tables if they don't exist.

Usage:
    python scripts/init_db.py
"""

import sys
from pathlib import Path

# Add project root to sys.path so we can import ``app``
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Config
from app.database import init_db


def main() -> None:
    cfg = Config.from_env()
    print(f"Initialising database: {cfg.database_url}")

    # Ensure the data/ directory exists
    db_path = cfg.database_url.replace("sqlite:///", "")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    init_db(cfg.database_url)
    print("✔  All tables created successfully.")


if __name__ == "__main__":
    main()
