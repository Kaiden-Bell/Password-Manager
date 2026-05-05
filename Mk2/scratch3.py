import nacl.secret
import nacl.utils

key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
box = nacl.secret.SecretBox(key)
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
encrypted = box.encrypt(b"hello", nonce)

print("len(encrypted):", len(encrypted))
print("len(encrypted.ciphertext):", len(encrypted.ciphertext))

# To decrypt, what works?
try:
    print("Decrypting whole without nonce:")
    res = box.decrypt(encrypted)
    print("Success:", res)
except Exception as e:
    print("Error:", e)

try:
    print("Decrypting whole WITH nonce:")
    res = box.decrypt(encrypted, nonce)
    print("Success:", res)
except Exception as e:
    print("Error:", e)

try:
    print("Decrypting ciphertext with nonce:")
    res = box.decrypt(encrypted.ciphertext, nonce)
    print("Success:", res)
except Exception as e:
    print("Error:", e)

try:
    print("Decrypting ciphertext WITHOUT nonce:")
    res = box.decrypt(encrypted.ciphertext)
    print("Success:", res)
except Exception as e:
    print("Error:", e)

