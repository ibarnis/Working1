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
import numpy as np
def aes_encrypt_pic(key: str, plaintext: str) -> str:
	"""
	Encrypts plaintext using AES-CBC with a given key.
	Returns the base64 encoded ciphertext and initialization vector (IV).
	"""
	# Generate a random 16-byte IV
	iv = urandom(16)
	key = key[:32]
	
	# Create an AES cipher object with the given key and IV
	cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

	# Pad the plaintext to be a multiple of 16 bytes using PKCS7 padding
	plaintext = pad(plaintext, AES.block_size, style='pkcs7')

	# Encrypt the padded plaintext
	ciphertext = cipher.encrypt(plaintext)

	# Combine the IV and ciphertext and return the base64 encoding
	iv_and_ciphertext = iv + ciphertext
	return base64.b64encode(iv_and_ciphertext).decode(), iv 
	
def connect():
	# Send "connect" message to the server
   # self.client_socket.sendall(iv_and_encrypted_message)


	# Capture video frames and send them to the server
	cap = cv2.VideoCapture(0)
	chunk_size = 1024
	for i in range(1):
		# Capture frame
		ret, frame = cap.read()
		data = image_to_bts(frame)
		print(frame)

		# Encrypt the data
		iv, encrypted_data = aes_encrypt_pic("12345678123456781234567812345678", data)
		print(f"Sending encrypted data of size {len(encrypted_data)} bytes...")


		
		#self.client_socket.sendall(encrypted_data)
		
	print("open_picture")
	open_picture(encrypted_data)
	# Release resources
	cap.release()

def image_to_bts(frame):
    '''
    :param frame: WxHx3 ndarray
    '''
    _, bts = cv2.imencode('.webp', frame)
    bts = bts.tobytes()
    return bts

def bts_to_img(bts):
    '''
    :param bts: results from image_to_bts
    '''
    buff = np.frombuffer(bts, np.uint8)
    img = cv2.imdecode(buff, cv2.IMREAD_COLOR)
    return img
    
def aes_decrypt(key: str, ciphertext: str, iv: bytes) -> str:
	"""
	Decrypts ciphertext that was encrypted with AES-CBC using a given key.
	Expects the ciphertext to be base64 encoded, with the IV prepended.
	"""
	print("0")
	try:
		key = "12345678123456781234567812345678"
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

		return plaintext

	except Exception as e:
		print("Error in aes_decrypt:", e)
		return ""
		
def open_picture(encrypted_data):
	# Decrypt the data
	iv = encrypted_data[:16]
	ciphertext = encrypted_data[16:]
	decrypted_data = aes_decrypt("12345678123456781234567812345678", ciphertext, iv)
	frame = bts_to_img(decrypted_data)
	cv2.imshow("frame", frame)
connect()