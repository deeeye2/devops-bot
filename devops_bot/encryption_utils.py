import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Constants
VAULT_FOLDER = os.path.expanduser("~/vault")
SALT = b'salt_'  # Use a secure method to generate and store your salt

def setup_vault(password):
    os.makedirs(VAULT_FOLDER, exist_ok=True)
    save_key(password)

def encrypt_vault(password):
    key = load_key(password)
    for filename in os.listdir(VAULT_FOLDER):
        if filename != 'key':
            encrypt_file(os.path.join(VAULT_FOLDER, filename), key)

def decrypt_vault(password):
    key = load_key(password)
    for filename in os.listdir(VAULT_FOLDER):
        if filename != 'key':
            decrypt_file(os.path.join(VAULT_FOLDER, filename), key)

def generate_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use the correct SHA256 class
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def save_key(password):
    key = generate_key(password)
    encoded_key = urlsafe_b64encode(key)
    with open(os.path.join(VAULT_FOLDER, 'key'), 'wb') as key_file:
        key_file.write(encoded_key)

def load_key(password):
    return generate_key(password)

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CFB8(b'0000000000000000'), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CFB8(b'0000000000000000'), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    with open(file_path, 'wb') as f:
        f.write(decrypted_data)
