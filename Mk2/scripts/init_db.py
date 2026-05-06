"""
init_db.py — Initialize the PostgreSQL database.

Creates all tables defined in the schema.
Run from project root:
    python scripts/init_db.py
"""

import sys
import os
import psycopg2

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import db
from app.config import DATABASE_URL


def create_database_if_not_exists(url: str):
    # Parse the URL to connect to the default 'postgres' database
    # Assuming URL format: postgresql://user:pass@host:port/dbname
    base_url = url.rsplit('/', 1)[0] + '/postgres'
    dbname = url.rsplit('/', 1)[1]
    
    try:
        conn = psycopg2.connect(base_url)
        conn.autocommit = True
        cursor = conn.cursor()
        
        cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (dbname,))
        exists = cursor.fetchone()
        
        if not exists:
            print(f"Creating database {dbname}...")
            cursor.execute(f"CREATE DATABASE {dbname}")
            
        conn.close()
    except psycopg2.OperationalError as e:
        print(f"Failed to connect to PostgreSQL server: {e}")
        print("Please ensure PostgreSQL is running and credentials in config.py are correct.")
        sys.exit(1)


def main():
    print(f"Connecting to server and ensuring database exists...")
    create_database_if_not_exists(DATABASE_URL)
    
    print(f"Initializing tables at: {DATABASE_URL}")
    db.initialize_database()
    print("Database initialized successfully.")


if __name__ == "__main__":
    main()
