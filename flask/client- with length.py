import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import socket
import struct

# Create an OpenCV capture object for the camera
cap = cv2.VideoCapture(0)

# Capture a frame from the camera
ret, frame = cap.read()

# Convert the frame to RGB color space
frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

# Create an AES encryption key and initialization vector (IV)
key = b'Sixteen byte key'
iv = b'Sixteen byte IV!'
iv = iv.ljust(16, b'\0') # Pad the IV to 16 bytes

# Create an AES cipher object
cipher = AES.new(key, AES.MODE_CBC, iv)

# Encrypt the frame using AES CBC mode
encrypted_data = cipher.encrypt(pad(frame.tobytes(), AES.block_size))

# Get the length of the encrypted data in bytes
length = len(encrypted_data)

# Pack the length into a 4-byte binary string
length_bytes = struct.pack('!I', length)

# Create a socket object
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
server_address = ('localhost', 10000)
sock.connect(server_address)

# Send the length of the encrypted data to the server
sock.sendall(length_bytes)

# Send the encrypted data to the server
sock.sendall(encrypted_data)

# Close the socket and release the capture object
sock.close()
cap.release()
