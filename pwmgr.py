"""
Password Manager
- Utilities (base64 helpers, safe JSON IO)
- Argon2id KDF + HKDF subkeying
- XChaCha20-Poly1305 AEAD encrypt/decrypt
- Device keypair create/load (X25519)
- Create new vault (passphrase wrap + device wrap)
- Unlock with passphrase or device


Dependencies (inside your venv):
pip install pynacl argon2-cffi cryptography
"""

from __future__ import annotations
import base64 
import json
import os
import sys
import threading
import time

try:
    import pyperclip
except ImportError:
    pyperclip = None

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple

from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from nacl import utils as nacl_utils
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt
)
from nacl.public import PrivateKey, PublicKey, SealedBox


def b64e(b):
    return base64.b64encode(b).decode("utf-8")
def b64d(s):
    return base64.b64decode(s.encode("utf-8"))

VAULT_DEFAULT_PATH = Path.home() / "vault.kv.json"
DEVICE_KEY_PATH = Path.home() / ".local" / "share" / "pwmgr" / "device.key"
DEVICE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)

# ====================
# === KEY CREATION ===
# ====================

def argon2id_kdf(passphrase, *, salt, m_kib = 262_144, t = 3, p = 1, outlen = 32):
    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt, 
        t, 
        m_kib, 
        p, 
        outlen,
        Argon2Type.ID,
    )

def hkdf_subkey(keyMaterial, *, info, outlen = 32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=outlen,
        salt=None,
        info=info,
    )
    return hkdf.derive(keyMaterial)

def aead_encrypt_xchacha(key, plaintext, ad=b""):
    nonce = nacl_utils.random(24)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)
    return nonce, ct

def aead_decrypt_xchacha(key, nonce, ct, ad=b""):
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ct, ad, nonce, key)



# =========================
# === DEVICE MANAGEMENT ===
# =========================

def loadSlashCreateDeviceKey(path = DEVICE_KEY_PATH):
    if path.exists():
        with open(path, "rb") as f:
            return PrivateKey(f.read())
    sk = PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)

    try: 
        oldUmask = os.umask(0o177)
        with open(path, "wb") as f:
            f.write(bytes(sk))
    finally:
        os.umask(oldUmask)
    return sk

# ===============================
# === Vault creation + unlock ===
# ===============================

def createVault(*, passphrase, devices):

    # Rand 32 byte master key
    vmk = nacl_utils.random(32) 

    # Wrap VMK with passphrase
    salt = os.urandom(16)
    kdfKey = argon2id_kdf(passphrase, salt=salt)
    wrapKey = hkdf_subkey(kdfKey, info=b"vmk-wrap-passphrase")
    ppNonce, ppCt = aead_encrypt_xchacha(wrapKey, vmk)

    # Wrap VMK to each device pub key through sealed box
    devEntries = []
    for dev in devices:
        pub = PublicKey(b64d(dev["pub"]))
        sealed = SealedBox(pub).encrypt(vmk)
        devEntries.append({
            "device_id": dev["device_id"],
            "pub": b64e(bytes(pub)),
            "sealed_vmk": b64e(sealed),
        })
    
    # Empty json entries
    entries = {"items": []}
    vNonce, vCt = aead_encrypt_xchacha(vmk, json.dumps(entries).encode("utf-8"))

    vault = {
        "version": 1,
        "alg": "xchacha20poly1305",
        "kdf": {
            "type": "Argon2id",
            "salt": b64e(salt),
            "time_cost": 3,
            "memory_kib": 262_144,
            "parallelism": 1,
        },
        "vmk_wrapped": {
            "passphrase": {
                "nonce": b64e(ppNonce),
                "ciphertext": b64e(ppCt),
            },
            "devices": devEntries,
        },
        "vault": {
            "nonce": b64e(vNonce),
            "ciphertext": b64e(vCt),
        },
    }
    return vault

def unlockWithPassphrase(vault, passphrase):
    kdf = vault["kdf"]
    salt = b64d(kdf["salt"])
    kdfKey = argon2id_kdf(passphrase, salt=salt, m_kib=kdf["memory_kib"], t=kdf["time_cost"], p=kdf["parallelism"])
    wrapKey = hkdf_subkey(kdfKey, info=b"vmk-wrap-passphrase")

    pp = vault["vmk_wrapped"]["passphrase"]
    vmk = aead_decrypt_xchacha(wrapKey, b64d(pp["nonce"]), b64d(pp["ciphertext"]))

    v = vault["vault"]
    pt = aead_decrypt_xchacha(vmk, b64d(v["nonce"]), b64d(v["ciphertext"]))
    return vmk, json.loads(pt.decode("utf-8"))


def unlockWithDevice(vault, privKey):
    sk = PrivateKey(privKey)
    myPubB64 = b64e(bytes(sk.public_key))

    dentry = None
    for d in vault["vmk_wrapped"]["devices"]:
        if d["pub"] == myPubB64:
            dentry = d
            break
    if dentry is None:
        raise RuntimeError("This device is not authorized in the vault!")
    
    vmk = SealedBox(sk).decrypt(b64d(dentry["sealed_vmk"]))
    v = vault["vault"]
    pt = aead_decrypt_xchacha(vmk, b64d(v["nonce"]), b64d(v["ciphertext"]))
    return vmk, json.loads(pt.decode("utf-8"))

# ====================
# === Password Gen ===
# ====================

import secrets

def genPass(length = 20, *, symbols = True, noLookalikes = True):
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "23456789" if noLookalikes else "0123456789"
    sym = "!@#$%^&*()-_=+[];,.?/|" if symbols else ""
    lookalikeStrip = "Il1O0|" if noLookalikes else ""
    alphabet = "".join(ch for ch in (letters + digits + sym) if ch not in lookalikeStrip)
    return "".join(secrets.choice(alphabet) for _ in range(length))

def unlockForUpdate(*, passphrase=None, path=VAULT_DEFAULT_PATH, device_key_path=DEVICE_KEY_PATH):
    """
    Ret (vault_dict, vmk_bytes, entries_dict)

    :param passphrase: User def passphrase to unlock vault
    :param path: Path to vault
    :param device_key_path: Path to device key
    """

    with open(path) as f:
        vault = json.load(f)
    
    if passphrase is not None:
        vmk, entries = unlockWithPassphrase(vault, passphrase)
        return vault, vmk, entries
    
    try:
        with open(device_key_path, "rb") as f:
            sk = f.read()
        vmk, entries = unlockWithDevice(vault, sk)
        return vault, vmk, entries
    except FileNotFoundError:
        raise RuntimeError("Device Key not found! Provide passphrase or run device init!")
    except Exception as e:
        raise RuntimeError(f"Device unlock failed {e}. Try --passphrase")
    
def updateVaultPayload(vault, vmk, entries):

    vNonce, vCt = aead_encrypt_xchacha(vmk, json.dumps(entries).encode("utf-8"))
    vault["vault"]["nonce"] = b64e(vNonce)
    vault["vault"]["ciphertext"] = b64e(vCt)

    return vault

# =========================
# === Clipboard Helpers ===
# =========================

def copy_to_clipboard(secret, *, clear_after = 30):
    if pyperclip is None:
        print("⚠️ Clipboard support not avaliable")
        return
    
    try: 
        pyperclip.copy(secret)
    except Exception as e:
        print(f"Failed to copy to clipboard: {e}")
        return

    print(f"📋 Password copied for {clear_after} seconds.")

    def _clear():
        time.sleep(clear_after)

        try: 
            if pyperclip.paste() == secret:
                pyperclip.copy("")
                print("\n🧹 Clipboard cleared.")
        except Exception:
            pass

    t = threading.Thread(target=_clear, daemon=True)
    t.start()


# ================
# === Drivers! ===
# ================

def cmd_device_init():
    sk = loadSlashCreateDeviceKey()
    print("✅ Device key ready.")
    print("Public Key (base64) - copy for init: ")
    print(b64e(bytes(sk.public_key)))

def cmd_vault_init(passphrase, device_id, device_pub_b64, *, output, path = VAULT_DEFAULT_PATH):
    devices = [{"device_id": device_id, "pub": device_pub_b64}]
    vault = createVault(passphrase=passphrase, devices=devices)
    with open(output, "w") as f:
        json.dump(vault, f, indent=2)
    print(f"✅ Vault created at {output}")

def cmd_test_unlock(passphrase, path = VAULT_DEFAULT_PATH):
    with open(path) as f:
        vault = json.load(f)
    vmk, entries = unlockWithPassphrase(vault, passphrase)
    print("✅ Passphrase unlock OK. Items:", len(entries.get("items", [])))


def cmd_test_device_unlock(*, path = VAULT_DEFAULT_PATH, device_key_path = DEVICE_KEY_PATH):
    with open(path) as f:
        vault = json.load(f)
    with open(device_key_path, "rb") as f:
        sk = f.read()
    vmk, entries = unlockWithDevice(vault, sk)
    print("✅ Device unlock OK. Items:", len(entries.get("items", [])))

def cmd_add(site, username, *, notes="", length=20, passphrase=None, path=VAULT_DEFAULT_PATH, device_key_path=DEVICE_KEY_PATH):
    vault, vmk, entries = unlockForUpdate(passphrase=passphrase, path=path, device_key_path=device_key_path)
    pwd = genPass(length=length)
    items = entries.setdefault("items", [])

    today = datetime.now().strftime("%Y-%m-%d")
    items.append({
        "site": site,
        "username": username,
        "password": pwd,
        "notes": notes,
        "today": today,
        "last_rotated": today,
    })

    updateVaultPayload(vault, vmk, entries)
    with open(path, "w") as f:
        json.dump(vault, f, indent=2)

    print(f"✅ Added entry for {site} ({username}).")
    print("Generated Password:")
    print(pwd)
    copy_to_clipboard(pwd, clear_after=20)

def cmd_get(site, *, username=None, passphrase=None, path=VAULT_DEFAULT_PATH, device_key_path=DEVICE_KEY_PATH):
    vault, vmk, entries = unlockForUpdate(passphrase=passphrase, path=path, device_key_path=device_key_path)

    items = entries.get("items", [])
    matches = []
    for item in items:
        if item.get("site") != site:
            continue
        if username is not None and item.get("username") != username:
            continue
        matches.append(item)

    if not matches:
        print(f"⚠️ No entries found for site='{site}'" + (f", username='{username}'" if username else ""))
        return 

    print(f"✅ Found {len(matches)} entr{'y' if len(matches) == 1 else 'ies'} for {site}:")
    for i, item in enumerate(matches, start=1):
        print("-" * 40)
        print(f"[{i}] site: {item.get('site')}")
        print(f"     username: {item.get('username')}")
        print(f"     password: {item.get('password')}")
        print(f"     created: {item.get('created')}")
        print(f"     rotated: {item.get('last_rotated')}")
        if item.get("notes"):
            print(f"    notes:    {item['notes']}")
    
    first = matches[0]
    pwd = first.get("password")
    if pwd:
        print(f"\n📋 Copying pass for site: {first.get('site')}, username: {first.get('username')} to clipboard.")
        copy_to_clipboard(pwd, clear_after=20)

def cmd_rotate(site, *, username=None, length=20, passphrase=None, path=VAULT_DEFAULT_PATH, device_key_path=DEVICE_KEY_PATH):
    vault, vmk, entries = unlockForUpdate(passphrase=passphrase, path=path, device_key_path=device_key_path)

    items = entries.get("items",[])
    target = None

    for item in items:
        if item.get("site") != site:
            continue
        if username is not None and item.get("username") != username:
            continue
        target = item
        break

 
    if target is None:
        print(f"⚠️ No entry found to rotate for site='{site}'" + (f", username='{username}'" if username else ""))
        return 

    new_pwd = genPass(length=length)
    today = datetime.now().strftime("%Y-%m-%d")
    target["password"] = new_pwd
    target["last_rotated"] = today

    updateVaultPayload(vault, vmk, entries)
    with open(path, "w") as f:
        json.dump(vault, f, indent=2)
    
    print(f"✅ Rotated password for {site}" + (f"({username})" if username else ""))
    print("New Password:")
    print(new_pwd)
    copy_to_clipboard(new_pwd, clear_after=20)
    



if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Password Manager Arguments")
    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("device-init", help="Create or load device key; print public key")

    s2 = sub.add_parser("vault-init", help="Create new vault with passphrase + this device")
    s2.add_argument("--device-id", required=True)
    s2.add_argument("--device-pub", required=True, help="Base64 device public key")
    s2.add_argument("--passphrase", required=True)
    s2.add_argument("--out", default=str(VAULT_DEFAULT_PATH))

    s3 = sub.add_parser("test-unlock", help="Test passphrase unlock")
    s3.add_argument("--passphrase", required=True)

    s4 = sub.add_parser("test-unlock-device", help="Test device unlock")

    s5 = sub.add_parser("add", help="Add a new entry (gen password)")
    s5.add_argument("site")
    s5.add_argument("--username", required=True)
    s5.add_argument("--notes", default="")
    s5.add_argument("--length", type=int, default=20)
    s5.add_argument("--passphrase", help="Unlock using this passphrase instead of device key")

    s6 = sub.add_parser("get", help="Get entry/entries for a site")
    s6.add_argument("site")
    s6.add_argument("--username", help="Filter by username")
    s6.add_argument("--passphrase", help="Unlock using this passphrase instead of device key")

    s7 = sub.add_parser("rotate", help="Rotate password for an entry")
    s7.add_argument("site")
    s7.add_argument("--username",help="Filter by username")
    s7.add_argument("--length", type=int, default=20)
    s7.add_argument("--passphrase", help="Unlock using this passphrase instead of device key")


    args = p.parse_args()

    if args.cmd == "device-init":
        cmd_device_init()
    elif args.cmd == "vault-init":
        cmd_vault_init(passphrase=args.passphrase, device_id=args.device_id, device_pub_b64=args.device_pub, output=Path(args.out))
    elif args.cmd == "test-unlock":
        cmd_test_unlock(passphrase=args.passphrase)
    elif args.cmd == "test-unlock-device":
        cmd_test_device_unlock()
    elif args.cmd == "add":
        cmd_add(site=args.site, username=args.username, notes=args.notes, length=args.length, passphrase=args.passphrase)
    elif args.cmd == "get":
        cmd_get(site=args.site, username=args.username, passphrase=args.passphrase)
    elif args.cmd == "rotate":
        cmd_rotate(site=args.site, username=args.username, length=args.length, passphrase=args.passphrase)
