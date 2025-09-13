# generate_key.py
from cryptography.fernet import Fernet

key = Fernet.generate_key()
with open("secret.key", "wb") as f:
    f.write(key)

print("Key saved to secret.key — copy this to both server and client")
