import nacl.secret
import nacl.utils

key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
box = nacl.secret.SecretBox(key)
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
encrypted = box.encrypt(b"hello", nonce)

print("len(encrypted):", len(encrypted))
print("len(encrypted.ciphertext):", len(encrypted.ciphertext))
print("len(encrypted.message):", len(encrypted.message))
print("len(nonce):", len(nonce))

# what if we decrypt the whole 'encrypted' without nonce?
try:
    print("Decrypting whole without nonce:", box.decrypt(encrypted))
except Exception as e:
    print("Error:", e)

