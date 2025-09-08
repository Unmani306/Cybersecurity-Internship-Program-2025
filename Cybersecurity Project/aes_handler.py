from cryptography.fernet import Fernet
from key_manager import load_or_generate_key

key = load_or_generate_key()

def aes_encrypt_file(file_path):
    fernet = Fernet(key)
    with open(file_path, 'r') as f:
        data = f.read()
    encrypted = fernet.encrypt(data.encode()).decode()
    new_file = file_path + ".enc"
    with open(new_file, 'w') as f:
        f.write(encrypted)
    return new_file

def aes_decrypt_file(file_path):
    fernet = Fernet(key)
    with open(file_path, 'r') as f:
        data = f.read()
    decrypted = fernet.decrypt(data.encode()).decode()
    new_file = file_path.replace(".enc", "_decrypted.txt")
    with open(new_file, 'w') as f:
        f.write(decrypted)
    return new_file
