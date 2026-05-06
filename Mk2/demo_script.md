# Password Manager Demo Script

**Project Title:** The Vault - Hardware-Gated Password Manager
**Duration:** ~3-5 minutes

## Introduction (0:00 - 0:30)
**Visuals:** Show the login/initialization screen of the web frontend. Show the terminal where the FastAPI backend (`app/main.py`) is running. Show the connected Arduino hardware (if applicable).
**Narration:** 
"Hello, this is a demonstration of 'The Vault', a locally hosted, encrypted password manager with hardware-gated security. The system uses a FastAPI Python backend, a basic HTML/JS frontend, and a PostgreSQL database. To start the program, please type in `uvicorn app.main:app --host [IP_ADDRESS] --port 8000 --reload` in your terminal. This will start the local server. To see the site, open your browser and navigate to `http://localhost:8000`.
Here you can see the application running locally and listening for API requests in the terminal the second you load into the site."





## System Initialization & Database Schema (0:30 - 1:15)
**Visuals:** Fill out the initialization form on the frontend (Username, Vault Name, Passphrase, Hardware PIN). Click "Initialize". Briefly show the `schema_dump.sql` or `database.py` file.
**Narration:**
"First, we initialize a new user and vault. When we submit this form, the application calls our Object-Oriented database layer to create records across several normalized PostgreSQL tables.
Specifically, it inserts a new user in the `users` table, creates a vault in the `vaults` table, and sets up security parameters in the `vault_policy` table. The application uses Argon2id for key derivation, generating a secure master key. The derived key data is securely stored in `auth_credentials`, and if hardware gating is enabled, the PIN hash is stored in `hardware_auth`. Notice that the database does not store the plaintext passphrase or the master key directly."

## Hardware Authentication & Application Code (1:15 - 2:00)
**Visuals:** Show the "Vault Locked" screen requesting hardware authentication. Enter the PIN on the physical Arduino keypad (or simulate the serial input). Show the backend terminal receiving the serial input.
**Narration:**
"The vault is currently locked. To unlock it, our policy requires a hardware gate. The application uses a background task defined in `serial_service.py` to listen for serial communication from the Arduino. When I enter the correct PIN on the Arduino keypad, the serial service reads the input, verifies it against the hashed PIN in the `hardware_auth` table, and opens a temporary, time-limited window for the software passphrase. All of these access attempts, both successful and failed, are recorded in the `access_logs` table for auditing."

## Software Passphrase & Data Decryption (2:00 - 2:45)
**Visuals:** Enter the software passphrase on the web interface. Transition into the unlocked Vault Dashboard. Show `crypto.py` and `database.py` side-by-side if possible.
**Narration:**
"Within the 60-second hardware window, we must now enter our software passphrase. The backend receives the passphrase, applies the Argon2id key derivation function using parameters from our database, and attempts to unwrap the encrypted master key. Upon success, the vault's status in the database is updated to 'UNLOCKED'. The encrypted blob containing our actual passwords is then fetched from the `vault_data` table and decrypted in memory using the XChaCha20-Poly1305 algorithm."

## Managing Passwords (2:45 - 3:30)
**Visuals:** Add a new password entry (e.g., 'GitHub', 'myusername', use the password generator). View the entry. Click "Logout".
**Narration:**
"Inside the vault, we can add, update, or view our passwords. We also have a secure password generator available. When a new password is saved, the application serializes all vault entries into a single JSON blob, encrypts the entire blob with the master key using a fresh cryptographic nonce, and updates the `vault_data` table. This ensures that even if the database file is compromised, the plaintext passwords remain secure. Finally, clicking logout clears the session, discards the in-memory master key, and locks the vault."

## Conclusion & Logs (3:30 - 4:00)
**Visuals:** Show the generated `database_logs.csv` file on screen, highlighting the different event types (INIT, HARDWARE_UNLOCK, SOFTWARE_UNLOCK, LOCK).
**Narration:**
"To conclude, here is an export of the `access_logs` table. You can clearly see the audit trail of our session: the initial creation, the hardware authentication success, the software unlock, and the final vault lock. This concludes the demonstration of the system's integration between the frontend, the FastAPI backend, the Arduino hardware, and the PostgreSQL database."
