import os
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Replace `from app import database` with `from app.database import db`
    # Replace `from app import crypto, database, session` with `from app import crypto, session\nfrom app.database import db`
    
    # We will do a generic replacement:
    # 1. Change how database is imported
    # 2. Change `database.method()` to `db.method()`
    
    original = content
    
    # Replace calls
    content = re.sub(r'\bdatabase\.(?=[a-z_]+\()', 'db.', content)

    # Replace specific import lines
    content = content.replace('from app import auth, vault, session, password_utils, database, hardware', 
                              'from app import auth, vault, session, password_utils, hardware\nfrom app.database import db')
    content = content.replace('from app import crypto, database, session, vault',
                              'from app import crypto, session, vault\nfrom app.database import db')
    content = content.replace('from app import crypto, database, session',
                              'from app import crypto, session\nfrom app.database import db')
    content = content.replace('from app import serial_service, hardware, database',
                              'from app import serial_service, hardware\nfrom app.database import db')
    content = content.replace('from app import auth, database',
                              'from app import auth\nfrom app.database import db')
    content = content.replace('from app.database import initialize_database',
                              'from app.database import db')
    content = content.replace('from app.database import (',
                              'from app.database import db # (')
    content = content.replace('import app.database as database',
                              'from app.database import db')
    content = content.replace('import app.database\napp.database.DATABASE_PATH = TEST_DB_PATH',
                              'from app.database import db\ndb.db_path = TEST_DB_PATH')
    content = content.replace('    from app import database',
                              '    from app.database import db')
                              
    # Specific fix for verify_db.py imports:
    content = content.replace('    initialize_database,\n', '')
    
    # Also fix initialize_database() calls
    content = re.sub(r'\binitialize_database\(\)', 'db.initialize_database()', content)
    
    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated {filepath}")

for root, _, files in os.walk('.'):
    for f in files:
        if f.endswith('.py') and f not in ['database.py', 'refactor.py', 'export_submission.py']:
            process_file(os.path.join(root, f))
