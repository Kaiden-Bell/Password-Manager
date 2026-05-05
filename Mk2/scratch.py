import nacl.secret
import nacl.utils

key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
box = nacl.secret.SecretBox(key)
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
encrypted = box.encrypt(b"hello", nonce)

try:
    box.decrypt(encrypted.ciphertext, nonce)
    print("Success with just ciphertext")
except Exception as e:
    print("Error with just ciphertext:", e)

try:
    box.decrypt(encrypted, nonce)
    print("Success with encrypted message")
except Exception as e:
    print("Error with encrypted message:", e)
