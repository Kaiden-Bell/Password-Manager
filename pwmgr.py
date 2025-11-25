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
    return base64.b64decode(s).encode("utf-8")

VAULT_DEFAULT_PATH = Path.home() / "vault.kv.json"
DEVICE_KEY_PATH = Path.home() / ".local" / "share" / "pwmgr" / "device.key"
DEVICE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)

# ====================
# === KEY CREATION ===
# ====================

def argon2id_kdf(passphrase, *, salt, mKib = 262_144, t = 3, p = 1, outlen = 32):
    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt, 
        t, 
        mKib, 
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

def aead_encrypt_xchacha(key, plaintext, ad = b""):
    nonce = nacl_utils.random(24)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)
    return nonce, ct

def aead_decrypt_xchacha(key, nonce, ct, ad=b""):
    return crypto_aead_xchacha20poly1305_ietf_encrypt(ct, ad, nonce, key)



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
            "device-id": dev["device-id"],
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
    kdfKey = argon2id_kdf(passphrase, salt=salt, mKib=["memory-kib"], t=kdf["time_cost"], p=kdf["parallelism"])
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
    for d in vault["vmk-wrapped"]["devices"]:
        if d["pub"] == myPubB64:
            dentry = d
            break
    if dentry is None:
        raise RuntimeError("This device is not authorized in the vault!")
    
    vmk = SealedBox(sk).decrypt(b64d(dentry["sealed-vmk"]))
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
    lookalikeStrip = "Il100|" if noLookalikes else ""
    alphabet = "".join(ch for ch in (letters + digits + sym) if ch not in lookalikeStrip)
    return "".join(secrets.choice(alphabet) for _ in range(length))

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

    args = p.parse_args()

    if args.cmd == "device-init":
        cmd_device_init()
    elif args.cmd == "vault-init":
        cmd_vault_init(passphrase=args.passphrase, device_id=args.device_id, device_pub_b64=args.device_pub, output=Path(args.out))
    elif args.cmd == "test-unlock":
        cmd_test_unlock(passphrase=args.passphrase)
    elif args.cmd == "test-unlock-device":
        cmd_test_device_unlock()

