import os
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# generate a random salt
def generate_salt():
    return os.urandom(16)

# generate a key using the password and salt
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

# encrypt a file
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

# decrypt a file
def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    file_data = fernet.decrypt(encrypted_data)
    with open(file_path, "wb") as file:
        file.write(file_data)

# generate a password hash
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# verify if the password matches the hash
def verify_password(password, password_hash):
    return hash_password(password) == password_hash
    

def save_user_password(email: str, password: str):
    # Connect to the database
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()

    # Create the table if it doesn't exist
    c.execute("CREATE TABLE IF NOT EXISTS passwords (email text unique, password text)")

    # Hash the password
    hashed_password = hash_password(password)

    # Save the hashed password to the database
    c.execute("INSERT INTO passwords (email, password) VALUES (?, ?)", (email, hashed_password))

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

def check_user_password(email: str, password: str):
    # Connect to the database
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()

    # Get the hashed password from the database
    c.execute("SELECT password FROM passwords WHERE email=?", (email,))
    result = c.fetchone()

    # Close the connection
    conn.close()

    # If the email is not in the database, return False
    if not result:
        return False

    # Verify the password
    hashed_password = result[0]
    return verify_password(password, hashed_password)