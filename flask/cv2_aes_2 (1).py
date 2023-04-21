import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

# Create an AES cipher object for encryption
encrypt_cipher = AES.new(key, AES.MODE_CBC, iv)

# Encrypt the frame using AES CBC mode
encrypted_data = encrypt_cipher.encrypt(pad(frame.tobytes(), AES.block_size)) #send to server

# Create a new AES cipher object for decryption
decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)

# Decrypt the encrypted data using the new AES cipher object
decrypted_data = decrypt_cipher.decrypt(encrypted_data)

# Convert the decrypted data to a numpy array
decrypted_frame = np.frombuffer(unpad(decrypted_data, AES.block_size), dtype=np.uint8).reshape(frame.shape)

# Display the original and decrypted frames side by side
cv2.imshow('Original', frame)
cv2.imshow('Decrypted', decrypted_frame)
cv2.waitKey(0)
cv2.destroyAllWindows()

# Release the capture object and close any open windows
cap.release()
cv2.destroyAllWindows()
