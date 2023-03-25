import subprocess
import os
import ctypes
import sys
import win32com.client
import whitelist
import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import win32api
import win32con
import win32security

path=r"C:\Users\User\Documents\cyber\project\enc_whitelist.db"
def main():
	"""
	Main function to encrypt the database
	"""
	# Define the encryption parameters
	print("2")
	password = b"my_password_storng!"
	salt = b"salt_used_for_deriving_key"
	iterations = 100000
	key_length = 32

	# Derive the encryption key from the password and salt
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_length, salt=salt, iterations=iterations, backend=default_backend())
	key = kdf.derive(password)
	print("Derived key:", key)

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
		chunk_size = 64 * 1024	# 64KB
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
	os.replace(encrypted_backup_path, path)
	# Set read-only permissions for all users
    

	# Close the connection
	conn.close()

def is_admin():
	"""
	Determine whether the current script has admin privilege
	@return: bool. whether the script is in admin mode
	"""
	try:
		return ctypes.windll.shell32.IsUserAnAdmin()
	except:
		return False

def rerun_as_admin():
	"""
	Rerun the script with administrator privileges
	"""
	print("3")
	# Get the command line arguments
	args = sys.argv[:]
	args.insert(0, sys.executable)

	# Build the command string
	cmd = '"{}" "{}"'.format(sys.executable, " ".join(args))

	# Run the command as administrator
	shell = win32com.client.Dispatch("WScript.Shell")
	shell.Run(cmd, 1, True)

if __name__ == "__main__":
	if is_admin():
		# If the script is already running as an administrator, run the main function
		main()
		print("1")
	else:
		# If the script is not running as an administrator, rerun it with admin privileges
		rerun_as_admin()
		main()
		