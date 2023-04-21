import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton
from PyQt5.QtCore import Qt
import socket
import json
from typing import Tuple
from Diffie_Hellman import DiffieHellman
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from os import urandom
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
from PyQt5.QtWidgets import QGridLayout
from Crypto.Util.Padding import pad, unpad
import threading
from Crypto.Cipher import AES
import cv2
import pickle
import struct
from PyQt5.QtGui import QImage
from PyQt5.QtGui import QPixmap
import time
from Crypto.Random import get_random_bytes
import numpy as np
from Crypto import Random

def aes_encrypt(key: str, plaintext: str) -> str:
	"""
	Encrypts plaintext using AES-CBC with a given key.
	Returns the base64 encoded ciphertext and initialization vector (IV).
	"""
	# Generate a random 16-byte IV
	iv = urandom(16)
	key = key[:32]
	
	# Create an AES cipher object with the given key and IV
	cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

	# Pad the plaintext to be a multiple of 16 bytes
	plaintext = pad(plaintext.encode(), AES.block_size)

	# Encrypt the padded plaintext
	ciphertext = cipher.encrypt(plaintext)

	# Combine the IV and ciphertext and return the base64 encoding
	iv_and_ciphertext = iv + ciphertext
	return base64.b64encode(iv_and_ciphertext).decode(),iv

def aes_encrypt_pic(key: str, plaintext: str) -> Tuple[str, bytes]:
    """
    Encrypts plaintext with AES-CBC using a given key.
    Returns the ciphertext (base64 encoded) and the IV.
    """
    try:
        key = key[:32]

        # Generate a random IV
        iv = Random.get_random_bytes(AES.block_size)

        # Create an AES cipher object with the given key and IV
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

        # Pad the plaintext
        plaintext = plaintext.encode('utf-8')
        padded_plaintext = pad(plaintext, AES.block_size, style='pkcs7')

        # Encrypt the padded plaintext
        ciphertext = cipher.encrypt(padded_plaintext)

        # Concatenate the IV and ciphertext, and base64 encode the result
        iv_and_ciphertext = iv + ciphertext
        encoded_iv_and_ciphertext = base64.b64encode(iv_and_ciphertext).decode()

        return encoded_iv_and_ciphertext, iv

    except Exception as e:
        print("Error in aes_encrypt:", e)
        return "", bytes()

def aes_decrypt(key: str, ciphertext: str, iv: bytes) -> str:
	"""
	Decrypts ciphertext that was encrypted with AES-CBC using a given key.
	Expects the ciphertext to be base64 encoded, with the IV prepended.
	"""
	print("0")
	try:
		key = key[:32]
		print("1")
		# Decode the base64 encoded ciphertext and separate the IV from the ciphertext
		iv_and_ciphertext = base64.b64decode(ciphertext.encode())
		print("2")
		ciphertext = iv_and_ciphertext[AES.block_size:]
		print("3")
		
		print(len(iv),"iv len")
		# Create an AES cipher object with the given key and IV
		cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
		print("4")

		# Decrypt the ciphertext and unpad the resulting plaintext
		plaintext = cipher.decrypt(ciphertext)
		print("5")
		plaintext = unpad(plaintext, AES.block_size)
		print("6")

		return plaintext.decode()

	except Exception as e:
		print("Error in aes_decrypt:", e)
		return ""
	
class Client(QWidget):

	
	def receive_messages(self):
		while True:
			try:
				# Receive a message from the server
				encrypted_data = self.client_socket.recv(1024)
				if len(encrypted_data) != 0:
					# Decrypt the message
					iv = encrypted_data[:16]
					ciphertext = encrypted_data[16:]
					plaintext_data = aes_decrypt(self.shared_key, ciphertext.decode(), iv)
					# Display the message in the UI
					self.message_display.append("Server: " + plaintext_data)
			except Exception as e:
				print(e)
				break

	def connect(self):
		# Send "connect" message to the server
		encrypted_message, iv = aes_encrypt(self.shared_key, "connect")
		iv_and_encrypted_message = iv + encrypted_message.encode()
		self.client_socket.sendall(iv_and_encrypted_message)
		print("Sent 'connect' message to server")

		# Capture video frames and send them to the server
		cap = cv2.VideoCapture(0)
		cnt = 1
		while cnt <= 5:
			# Capture frame
			ret, frame = cap.read()
			encode_param=[int(cv2.IMWRITE_JPEG_QUALITY),90]
			result, imgencode = cv2.imencode('.jpg', frame, encode_param)
			data = np.array(imgencode)
			stringData = base64.b64encode(data)
			ciphertext, iv = aes_encrypt_pic(self.shared_key, stringData.decode())
			length = struct.pack(">Q", len(ciphertext))
			self.client_socket.sendall(length)
			self.client_socket.send(iv)
			self.client_socket.send(ciphertext.encode('utf-8'))
			print(f'sent image {cnt}')
			cnt += 1
			time.sleep(0.095)

		# Release resources
		cap.release()

		# Wait for "OK" message from server
		while True:
			encrypted_data = self.client_socket.recv(1024)
			if len(encrypted_data) != 0:
				iv = encrypted_data[:16]
				ciphertext = encrypted_data[16:]
				plaintext_data = aes_decrypt(self.shared_key, ciphertext.decode(), iv)
				if plaintext_data == "OK":
					print("Received OK from server!")
					# Enable the send button
					self.send_button.setDisabled(False)
					break

		# Start the chat
		self.receive_thread = threading.Thread(target=self.receive_messages)
		self.receive_thread.start()

	   
		
	def send_message(self):
		# Get the message from the input field
		message = self.message_input.toPlainText()
		print ("client msg", message)
		if message.strip() == '':
			return

		# Encrypt and send the message to the server
		encrypted_message, iv = aes_encrypt(self.shared_key, message)
		iv_and_encrypted_message = iv + encrypted_message.encode()
		self.client_socket.sendall(iv_and_encrypted_message)
		print("sent to server")

		# Receive a response from the server
		self.client_socket.settimeout(10)  # set a timeout of 10 seconds
		try:
			encrypted_data = self.client_socket.recv(1024)
			if len(encrypted_data) != 0:
				iv = encrypted_data[:16]
				ciphertext = encrypted_data[16:]
				plaintext_data = aes_decrypt(self.shared_key, ciphertext.decode(), iv)
				self.message_display.append("You: " + message)
				self.message_display.append("Server: " + plaintext_data)
		except socket.timeout:
			self.message_display.append("Timeout: no response from server.")

		# Clear the input field
		self.message_input.clear()

	def quit(self):
		# Close the socket and quit the application
		self.client_socket.close()
		QApplication.quit()

	def __init__(self):
		super().__init__()

		# Define the server address and port
		self.server_address = ('localhost', 5005)

		# Create a socket object
		self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		# Connect to the server
		self.client_socket.connect(self.server_address)
		print("Connected to server:", self.server_address)

		# Create a DiffieHellman object and generate parameters
		self.dh = DiffieHellman()
		# Generate a new DiffieHellman key exchange object
		self.prime = self.dh.get_prime()
		self.generator = self.dh.get_generator()
		self.private_key = self.dh.get_private()

		# Serialize and send the public key to the client
		self.public_key = self.dh.generate_public_key()
		print("public_key client ",self.public_key)
		encoded_public_key= self.public_key.encode()
		self.client_socket.sendall(encoded_public_key)

		# Receive the server's public key and deserialize it
		self.server_public_key = self.client_socket.recv(1024).decode()
		print("Server public key:", self.server_public_key)

		# Generate and exchange the shared key
		self.shared_key = self.dh.generate_shared_key(self.server_public_key)

		# Create UI elements
		self.image_label = QLabel()
		self.message_display = QTextEdit()
		self.message_input = QTextEdit()
		self.send_button = QPushButton("Send")
		self.send_button.setDisabled(True)
		self.send_button.clicked.connect(self.send_message)
		self.connect_button = QPushButton("Connect")
		self.connect_button.clicked.connect(self.connect)
		self.quit_button = QPushButton("Quit")
		self.quit_button.clicked.connect(self.quit)
		


		# Create button layout
		button_layout = QHBoxLayout()
		button_layout.addWidget(self.send_button)
		button_layout.addWidget(self.quit_button)

		# Create message layout
		message_layout = QVBoxLayout()
		message_layout.addWidget(self.image_label)
		message_layout.addWidget(self.message_display)
		message_layout.addWidget(self.message_input)
		button_layout.addWidget(self.connect_button)

		# Add button layout and message layout to main layout
		self.layout = QGridLayout()
		self.layout.addLayout(message_layout, 0, 0, 1, 2)
		self.layout.addLayout(button_layout, 1, 0, 1, 2)
		self.setLayout(self.layout)

		# Set window properties
		self.setWindowTitle("Chat Client")
		self.setGeometry(100, 100, 500, 500)
		self.show()






if __name__ == '__main__':
	app = QApplication(sys.argv)
	client = Client()
	sys.exit(app.exec_())



