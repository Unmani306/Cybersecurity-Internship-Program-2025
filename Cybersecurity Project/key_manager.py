from cryptography.fernet import Fernet
import os

def load_or_generate_key():
    key_path = "keys/aes_key.key"
    if not os.path.exists("keys"):
        os.mkdir("keys")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_path, "wb") as f:
            f.write(key)
        return key
