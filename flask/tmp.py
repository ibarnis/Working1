import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import socket

# Create an AES encryption key and initialization vector (IV)
key = b'Sixteen byte key'
iv = b'Sixteen byte IV!'
iv = iv.ljust(16, b'\0') # Pad the IV to 16 bytes

# Create a socket object and bind it to a port
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

# Wait for a client to connect
print('Waiting for a client to connect...')
connection, client_address = sock.accept()
print('Client connected:', client_address)

# Receive the encrypted data from the client
data = b''
while True:
    chunk = connection.recv(1024)
    if not chunk:
        break
    data += chunk

# Create an AES cipher object for decryption
cipher = AES.new(key, AES.MODE_CBC, iv)

# Decrypt the data using the AES cipher object
decrypted_data = cipher.decrypt(data)

# Convert the decrypted data to a numpy array
frame = np.frombuffer(unpad(decrypted_data, AES.block_size), dtype=np.uint8).reshape((480, 640, 3))

# Display the decrypted frame
cv2.imshow('Decrypted Frame', frame)
cv2.waitKey(0)
cv2.destroyAllWindows()

# Close the connection and socket
connection.close()
sock.close()
