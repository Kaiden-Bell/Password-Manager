import psycopg2
from psycopg2.extras import RealDictCursor
import csv
import subprocess
import sys
from app.config import DATABASE_URL

def get_pg_dump_path():
    import shutil
    import os
    if shutil.which("pg_dump"):
        return "pg_dump"
    base_path = r"C:\Program Files\PostgreSQL"
    if os.path.exists(base_path):
        for folder in os.listdir(base_path):
            pg_dump = os.path.join(base_path, folder, "bin", "pg_dump.exe")
            if os.path.exists(pg_dump):
                return pg_dump
    return "pg_dump"

def main():
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    except psycopg2.OperationalError as e:
        print(f"Could not connect to database: {e}")
        sys.exit(1)

    # Exports database_logs.csv for submission
    with open('database_logs.csv', 'w', newline='', encoding='utf-8') as f:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM access_logs")
        rows = cursor.fetchall()
        
        if rows:
            writer = csv.writer(f)
            writer.writerow(rows[0].keys())
            for row in rows:
                writer.writerow(row.values())
        print("Exported database_logs.csv")
    
    conn.close()

    pg_dump_cmd = get_pg_dump_path()

    # Exports schema_dump.sql for submission
    print("Exporting schema_dump.sql...")
    try:
        subprocess.run([pg_dump_cmd, DATABASE_URL, "--schema-only", "-f", "schema_dump.sql"], check=True)
        print("Exported schema_dump.sql")
    except subprocess.CalledProcessError as e:
        print(f"Failed to export schema: {e}")
    except FileNotFoundError:
        print("pg_dump not found. Ensure PostgreSQL bin directory is in your PATH.")

    # Exports data_dump.sql for submission
    print("Exporting data_dump.sql...")
    try:
        subprocess.run([pg_dump_cmd, DATABASE_URL, "--data-only", "--inserts", "-f", "data_dump.sql"], check=True)
        print("Exported data_dump.sql")
    except subprocess.CalledProcessError as e:
        print(f"Failed to export data: {e}")
    except FileNotFoundError:
        pass # Error already printed above

if __name__ == "__main__":
    main()
