import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import subprocess
import ctypes
import whitelist


# Define the encryption parameters
password = b"my_password"
salt = os.urandom(16)
iterations = 100000
key_length = 32

# Derive the encryption key from the password and salt
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_length, salt=salt, iterations=iterations, backend=default_backend())
key = kdf.derive(password)

# Connect to the SQLite database
conn = whitelist.main()

# Set the encryption key
conn.execute("PRAGMA key='{}';".format(key.decode('latin-1')))

# Get the SQLite database cursor
cursor = conn.cursor()

# Generate a random initialization vector
iv = os.urandom(16)

# Create a new cipher instance
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

# Create an unencrypted backup of the database
unencrypted_backup_path = "unencrypted_backup.db"
with sqlite3.connect(unencrypted_backup_path) as backup_conn:
    conn.backup(backup_conn, pages=1, name="main")

# Encrypt the backup file
encrypted_backup_path = "encrypted_backup.db"
with open(unencrypted_backup_path, "rb") as f_in, open(encrypted_backup_path, "wb") as f_out:
    encryptor = cipher.encryptor()
    chunk_size = 64 * 1024  # 64KB
    while True:
        chunk = f_in.read(chunk_size)
        if len(chunk) == 0:
            break
        elif len(chunk) % 16 != 0:
            # Pad the last chunk if needed
            chunk += b' ' * (16 - len(chunk) % 16)
        encrypted_chunk = encryptor.update(chunk)
        f_out.write(encrypted_chunk)

# Replace the unencrypted database with the encrypted backup
os.replace(encrypted_backup_path, "my_database.db")

# Close the connection
conn.close()
