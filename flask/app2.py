from flask import Flask, redirect, url_for, render_template, request
import hashlib
import sys,os
sys.path.append('..')
import whitelist
import sendMail
from new_tmp_capture import Capture
import sqlite3
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from PIL import Image
from io import BytesIO
from functools import wraps
from flask import Response, abort
from search_for_face import SvcDoRun
from functools import wraps
from cryptography.hazmat.primitives import padding
from flask import request, abort
import threading
import time
import ssl
from Diffie_Hellman import DiffieHellman
from random import choice
from Crypto.Util.Padding import pad, unpad
from string import ascii_letters, digits
from hashlib import sha256
from base64 import b64encode
from typing import List,Tuple
from datetime import datetime
from Crypto.Cipher import AES
from os import urandom
import socket, cv2
import pickle
import struct
import numpy as np

import face_in_frame

# dictionary to store all registered clients and their shared keys
users = {}
app = Flask(__name__)
database = r"..\whiteList.db"
password_admin=""
key=""
is_in_white=0
HOST = 'localhost'
PORT = 5005
clients = []

class Client():
	def __init__(self,socket,shared_key):
		self.socket=socket
		self.shared_key=shared_key
		self.name=None

@app.route('/loading.html')
def loading():
	message = "Look at the camera straight. Remove glasses and accessories."
	return render_template("loading.html", message=message)


@app.route('/index.html')
@app.route('/')
def hello():
	return render_template('index.html')

@app.route('/requestSent')
def requestSent():
	return render_template("requestSent.html")


@app.route('/accepted.html')

@app.route('/Home_security.html')
def Home_security():
	return render_template("Home_security.html")

@app.route('/Login.html')
def Login():
	return render_template("Login.html")


	
# Define the new login route to handle form submission
@app.route('/login2.html', methods=['GET', 'POST'])
def login2():
	error = None
	if request.method == 'POST':
		whitelist.main()
		real_pass = whitelist.get_password()
		real_user = whitelist.get_username()
		print(real_pass)
		if 'password' in request.form:
			password = request.form['password'].encode()
			# handle the case where the password is missing
			if not password:
				error = 'Password is required.'
				return render_template('/login2.html', error=error)
			
			# hash with SHA-2 (SHA-256 & SHA-512)
			password = hashlib.sha256(password).hexdigest()
			print(password)
			
			if request.form['username'] != real_user or password != real_pass:
				error = 'Invalid Credentials. Please try again.'
				return render_template('/login2.html', error=error)
			
			password_admin = password
			print("redirect")
			return redirect('/check_in_white_list')
		
	return render_template('/login2.html', error=error)


		


	
@app.route("/upload", methods=['POST'])
def upload():
	return "upload endpoint"

@app.route('/Register.html', methods=['GET', 'POST'])
def register():
	error = None
	if request.method == 'POST':
		print('hiii')
		mail = sendMail.Mail()
		print(request.form['email'])
		mail.send(request.form['email'], 'SECURED_ROOM', 'The admin got notified for your request')
		print('sent email')
		mail.send('barnisus@gmail.com', 'new registration', 'check the web. decide if you want to accept him')
		print('sent email')
		
		if request.form['email'] == '' or request.form['name'] == '':
			error = 'Invalid Credentials. Please try again.'
		else:
			email = request.form['email']
			name = request.form['name']
			threading.Thread(target=Capture(name, email).capturing).start()
			return redirect('/loading.html')
	return render_template('Register.html', error=error)

	
# Define the check_auth and authenticate functions for authentication
def check_auth(username, password):
	whitelist.main()
	real_pass = whitelist.get_password()
	real_user = whitelist.get_username()

	# hash with SHA-2 (SHA-256 & SHA-512)
	hashed_password = hashlib.sha256(password.encode()).hexdigest()

	if username == real_user and hashed_password == real_pass:
		return True
	else:
		return False

def authenticate():
	auth = request.authorization
	if not auth or not check_auth(auth.username, auth.password):
		return Response(
			'Could not verify your login details. Please try again.', 
			401, 
			{'WWW-Authenticate': 'Basic realm="Login Required"'}
		)

	session['logged_in'] = True
	return redirect('/admin_in')

def requires_auth(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		auth = request.authorization
		if not auth or not check_auth(auth.username, auth.password):
			return authenticate()
		return f(*args, **kwargs)
	return decorated

# Define the login route to handle form submission
@app.route('/Login.html', methods=['POST'])
def login():
	error = None
	if request.method == 'POST':
		whitelist.main()
		real_pass = whitelist.get_password()
		real_user = whitelist.get_username()
		print(real_pass)
		# encode it to bytes using UTF-8 encoding
		password = request.form['password'].encode()
		# hash with SHA-2 (SHA-256 & SHA-512)
		password= hashlib.sha256(password).hexdigest()
		print(password)
		if request.form['username'] != real_user or password != real_pass:
			error = 'Invalid Credentials. Please try again.'
		else:
			password_admin=password
			return redirect('/admin_in')
	return render_template('/Login.html', error=error)


	
	
# Define the admin_in route, protected by authentication
@app.route('/admin_in')
@requires_auth
def new_registration_details():
	# Retrieve the new registration requests from the database
	requests = get_new_registration_requests_from_database()

	# Prepare the data for each request for display in the template
	data = []
	for request in requests:
		name, email, picture_data = request[0], request[2], request[4]
		print(picture_data)
		try:
			# Encode the image data in base64
			base64_message = picture_data.decode('ascii')
			print(base64_message)
		except Exception as e:
			print(f"Error encoding image for {name}: {e}")
			base64_message = None
		data.append({'name': name, 'email': email, 'picture_base64': base64_message})

	# Render the template with the requests or with an error message
	if data:
		return render_template('admin_in.html', data=data)
	else:
		return render_template('admin_in.html', message="No new registration requests found.")
		


@app.route('/client_send_pic.html')
def client_send_pic():
	return render_template('client_send_pic.html')
	
@app.route('/user', methods=['POST','GET'])
def user():
	return render_template('user.html')

@app.route('/validate', methods=['POST'])
def validate():
	frame_data_url = request.form['frame']
	pil_image = Image.open(BytesIO(base64.b64decode(frame_data_url.split(',')[1])))
	if check_for_face(pil_image):
		if Capture_And_Compare().capturing() == 1:
			return redirect('/user')
	return redirect('/')
	
def check_for_face(frame):
	face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
	gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
	faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5)
	return len(faces) > 0


	
@app.route('/deny_registration', methods=['POST'])
def deny_registration():
	email = request.form.get("email")
	delete_request_from_database(email)
	return redirect(url_for("new_registration_details"))




def requires_in_white_list(func):
	@wraps(func)
	def decorated_function(*args, **kwargs):
		if is_in_white == 1:
			print("i can enter")
			return func(*args, **kwargs)
		else:
			abort(403)	  # Forbidden
	return decorated_function


@app.route('/white_space')
@requires_in_white_list
def in_white_list():
	print("in_white_list")
	return render_template('white_space.html')



@app.route('/check_in_white_list', methods=['GET', 'POST'])
def check_in_white_list():
		global is_in_white
		if request.method == 'POST' and 'from_index' in request.form and request.form['from_index'] == 'true':
			print("here3")
			return render_template('loading2.html')
			
			
		else:
			svc = SvcDoRun()
			
			svc.start()
			try:
				is_in_white = svc.is_completed()
				print("svc.is_completed() returned:", is_in_white)
			except Exception as e:
				print("Error occurred:", str(e))
				# Log the error
				app.logger.error("An error occurred while checking whitelist: %s", e)
				# Return an error message to the user
				return render_template("error.html", message="An error occurred while checking whitelist.")
			# Wait for the task to complete
			while is_in_white ==0:
				print("Waiting for result...")
				time.sleep(1)
				is_in_white = svc.is_completed()
				print("svc.is_completed() returned:", is_in_white)

			if is_in_white == 1:
				print("is_completed() returned 1 - redirecting to white_space.html")
				return redirect('/white_space')
			else:
				print("is_completed() returned 0 - rendering error.html")
				return render_template("error.html", message="Access Denied")
		

	




@app.route('/loading2.html')
def loading2():
	message = "Look at the camera straight. Remove glasses and accessories."
	return render_template("loading2.html", message=message)


@app.route('/poll_result')
def poll_result():
	is_in_white = SvcDoRun().is_completed()
	if is_in_white is None:
		return "0"
	elif is_in_white == 1:
		return "1"
	else:
		return "0"

		
def send_to_admin(email, name, picture):
	picture_filename = f"{email}_{picture.filename}"
	picture_path = os.path.join("uploads", picture_filename)
	
	if not os.path.exists("uploads"):
		os.makedirs("uploads")
	
	try:
		picture.save( picture_path )
	except Exception as e:
		print("An error occurred while saving the picture:", e)
		return

	conn = sqlite3.connect(database)
	c = conn.cursor()
	c.execute("CREATE TABLE IF NOT EXISTS requested (email text unique, name text, picture text)")
	c.execute("INSERT INTO requested (email, name, picture) VALUES (?, ?, ?)", (email, name, picture_path))
	conn.commit()
	conn.close()


	
@app.route('/accept_registration', methods=['POST'])
def accept_registration():
	email = request.form.get("email")
	conn = whitelist.create_connection(database)
	cursor = conn.cursor()
	cursor.execute("CREATE TABLE IF NOT EXISTS white (label text, email text, admin int, embedings blob, picture blob)")

	# Check if email exists in the requested table
	sqlite_select_query = """SELECT label, email, admin, embedings, picture FROM requested WHERE email = ?"""
	cursor.execute(sqlite_select_query, (email,))
	row = cursor.fetchone()
	if row is None:
		conn.close()
		flash("Email is already in the system.")
		return redirect('/')


	# Check if label already exists in the white table
	sqlite_select_query = """SELECT label FROM white WHERE label = ?"""
	cursor.execute(sqlite_select_query, (row[0],))
	existing_label = cursor.fetchone()
	if existing_label is not None:
		conn.close()
		return render_template('not_accepted.html')	 # Show custom error message

	try:
		# Add user to the white table
		cursor.execute("INSERT INTO white (label, email, admin, embedings) VALUES (?, ?, ?,?)", (row[0], row[1], row[2], row[3]))
		# Remove user from the requested table
		cursor.execute("DELETE FROM requested WHERE email = ?", (email,))
		conn.commit()
		conn.close()
		return render_template('accepted.html')
	except Exception as e:
		print("Error accepting registration: ", e)
		conn.close()
		return render_template('not_accepted.html')

def get_new_registration_requests_from_database():
	connection = sqlite3.connect(database)	# replace "whitelist" with the actual database file name
	cursor = connection.cursor()

	# Check if the "requested" table exists
	cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='requested'")
	result = cursor.fetchone()
	if not result:
		connection.close()
		return []

	cursor.execute("SELECT * FROM requested")
	requests = cursor.fetchall()
	connection.close()
	return requests

@app.route("/generate-keys", methods=["GET"])
def generate_keys():
	dh = DiffieHellman()
	private_key, public_key = dh.get_private_key(), dh.gen_public_key()
	return jsonify({"private_key": private_key, "public_key": public_key,})


@app.route("/generate-shared-key", methods=["GET"])
def generate_shared_key():
	try:
		local_private_key = request.args.get("local_private_key")
		remote_public_key = request.args.get("remote_public_key")
		shared_key = DiffieHellman.gen_shared_key_static(
			local_private_key, remote_public_key
		)
	except:
		return jsonify({"message": "Invalid public key"}), 400
	return jsonify({"shared_key": shared_key})
# Generate random username for new users
def generate_username() -> str:
	return "".join(choice(ascii_letters + digits) for _ in range(10))

# Register new user with a generated username and shared key
@app.route("/register_client", methods=["POST"])
def register_client():
	username = generate_username()
	dh = DiffieHellman()
	private_key, public_key = dh.get_private_key(), dh.generate_public_key()
	users[username] = {"private_key": private_key, "public_key": public_key}
	return jsonify({"username": username, "public_key": public_key})


# Get list of all online users
@app.route("/users", methods=["GET"])
def get_users():
	return jsonify({"users": list(users.keys())})


# Send a message from one user to another
@app.route("/message", methods=["POST"])
def send_message():
	sender = request.json.get("sender")
	recipient = request.json.get("recipient")
	message = request.json.get("message")
	timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	# Check if sender and recipient are registered users
	if sender not in users or recipient not in users:
		return jsonify({"message": "Invalid sender or recipient"}), 400

	# Check if sender and recipient have a shared key
	try:
		shared_key = DiffieHellman.generate_shared_key_static(
			users[sender]["private_key"], users[recipient]["public_key"]
		)
	except ValueError as e:
		return jsonify({"message": str(e)}), 400

	# Encrypt message with shared key
	encrypted_message = aes_encrypt(message.encode(), shared_key)

	# Send encrypted message to recipient
	recipient_key = users[recipient]["public_key"]
	encrypted_key = rsa_encrypt(shared_key.encode(), recipient_key)
	message_data = {"sender": sender, "message": b64encode(encrypted_message).decode(), "key": b64encode(encrypted_key).decode(), "timestamp": timestamp}
	return jsonify(message_data)


# Receive message sent to user
@app.route("/receive", methods=["POST"])
def receive_message():
	recipient = request.json.get("recipient")
	message = request.json.get("message")
	encrypted_key = request.json.get("key")
	timestamp = request.json.get("timestamp")

	# Check if recipient is a registered user
	if recipient not in users:
		return jsonify({"message": "Invalid recipient"}), 400

	# Decrypt shared key with recipient's private key
	try:
		private_key = users[recipient]["private_key"]
		shared_key = rsa_decrypt(b64decode(encrypted_key.encode()), private_key).decode()
	except ValueError as e:
		return jsonify({"message": str(e)}), 400

	# Decrypt message with shared key
	decrypted_message = aes_decrypt(b64decode(message.encode()), shared_key.encode()).decode()

	# Return decrypted message to recipient
	message_data = {"sender": recipient, "message": decrypted_message, "timestamp": timestamp}
	return jsonify(message_data)



	

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
		print(plaintext)
		plaintext = unpad(plaintext, AES.block_size)
		print("6")

		return plaintext.decode()

	except Exception as e:
		print("Error in aes_decrypt:", e)
		return ""

def is_valid_client(client,shared_key,my_iv):
	print(client,shared_key)
	pictures = receive_all_pictures(client,shared_key,my_iv)
	FaceFrame= face_in_frame.FaceFrame(pictures)
	valid,name = FaceFrame.is_face_valid()
	if valid==1:
		message="OK"
		try:
			message_bytes= message
			aes_encrypted_msg,iv=aes_encrypt(shared_key,message_bytes)
			iv_and_encrypted_message = iv + aes_encrypted_msg.encode()
			client.sendall(iv_and_encrypted_message)
			print(iv_and_encrypted_message)
			return True
		except Exception as e:
			print("Error broadcasting message to client:", e)
			clients.remove(client)
			client.close()
	else:
		return False

def handle_client(client: socket.socket, address: Tuple[str, int]) -> None:
	"""
	Handles a connection from a client.
	"""
	# Generate a new DiffieHellman key exchange object
	dh = DiffieHellman()
	# Generate a new DiffieHellman key exchange object
	prime = dh.get_prime()
	generator = dh.get_generator()

	private_key = dh.get_private()

	# Serialize and send the public key to the client
	public_key = dh.generate_public_key()
	encoded_public_key = public_key.encode()
	print("public_key server ", public_key)
	client.sendall(encoded_public_key)

	# Receive the client's public key and deserialize it
	client_public_key = client.recv(1024).decode()

	# Generate and exchange the shared key
	shared_key = dh.generate_shared_key(client_public_key)
	clients.append(Client(client,shared_key))
	print("shared", shared_key)

	# Wait for client to press connect before checking if it's valid
	while True:
		try:
			# Receive data from the client
			encrypted_data = client.recv(1024)
			try:
				iv = encrypted_data[:16]
				ciphertext = encrypted_data[16:]
				my_iv=iv
				print("!!!!!123")
				plaintext_data = aes_decrypt(shared_key, ciphertext.decode(), iv)
				if plaintext_data=="connect":
					print("connect!!")
					break
			except UnicodeDecodeError:
				print("Error decoding data from client:", data)
		except Exception as e:
			# Client has disconnected
			print("exception!", e)
			clients.remove(client)
			client.close()
			return

	# Check if the client is valid
	if is_valid_client(client, shared_key,my_iv):
		# Receive messages from the client and broadcast them to all connected clients
		while True:
			try:
				print("i am reciving")
				encrypted_data = client.recv(1024)
				print("recived")
				iv = encrypted_data[:16]
				ciphertext = encrypted_data[16:]
				print("!!!!!")
				plaintext_data = aes_decrypt(shared_key, ciphertext.decode(), iv)
				print(plaintext_data)
				print("here server")
				broadcast_message(plaintext_data, shared_key)

			except Exception as e:
				# Client has disconnected
				print("exception!", e)
				clients.remove(client)
				client.close()
				break
	else:
		print("client is a threat!")
		clients.remove(client)
		client.close()

def recvall(sock, n):
	# Helper function to receive n bytes or return None if EOF is hit
	data = b''
	print("n ",n)
	
	while len(data) < n:
		
		packet = sock.recv(n - len(data))
		if not packet:
			print(f"Error: Could not receive packet of size {n - len(data)}")
			return None
		print("packet ",packet)
		data += packet
		print(f"Received packet of size {len(packet)}")
		if len(packet) == 0:
			
			print("EOF reached, returning None")
			return None
	print("i am returning")
	return data
	
	
def receive_all_pictures(client, shared_key,my_iv):
	pictures = []
	num_pictures = 5
	my_iv = my_iv.ljust(16, b'\0') # Pad the IV to 16 bytes
	for i in range(num_pictures):
		try:
			# Receive the length of the encrypted data from the client
			length_bytes = b''
			while len(length_bytes) < 4:
				chunk = client.recv(4 - len(length_bytes))
				if not chunk:
					break
				length_bytes += chunk

			# Unpack the length from the 4-byte binary string
			length = struct.unpack('!I', length_bytes)[0]

			# Receive the encrypted data from the client
			data = b''
			while len(data) < length:
				chunk = client.recv(length - len(data))
				if not chunk:
					break
				data += chunk

			# Create an AES cipher object for decryption
			cipher = AES.new(shared_key[:16].encode(), AES.MODE_CBC, my_iv)
			print("shared_key[:16]",shared_key[:16])
			# Decrypt the data using the AES cipher object
			decrypted_data = cipher.decrypt(data)

			# Convert the decrypted data to a numpy array
			frame = np.frombuffer(unpad(decrypted_data, AES.block_size), dtype=np.uint8).reshape((480, 640, 3))

			# Display the decrypted frame
			#cv2.imshow('Decrypted Frame', frame)
			#cv2.waitKey(0)
			#cv2.destroyAllWindows()
			print("got frame")
			pictures.append(frame)
			print(pictures,"!")
		except Exception as e:
			print(f"Error receiving picture {i}: {e}")
			return None
			
	if len(pictures) != num_pictures:
		print(f"Error: Expected {num_pictures} pictures but received {len(pictures)}")
		return None

	return pictures	   

def broadcast_message(message,shared_key):
	"""
	Broadcasts a message to all connected clients.
	"""
	
	for client in clients:
		try:
			print("message",message)
			aes_encrypted_msg,iv=aes_encrypt(client.shared_key,message)
			print("aes_encrypted_msg",aes_encrypted_msg)
			iv_and_encrypted_message = iv + aes_encrypted_msg.encode()
			print("client.shared_key",client.shared_key)
			print("iv: " ,iv)
			print("encrypted_message: " ,aes_encrypted_msg)
			print("sending in broadcast")
			client.socket.sendall(iv_and_encrypted_message)
			
		except Exception as e:
			print("Error broadcasting message to client:", e)
			clients.remove(client)
			client.close()


def start_server() -> None:
	"""
	Starts the chat server and listens for incoming connections.
	"""
	# Create a new socket object and bind it to the specified address and port
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((HOST, PORT))
	server.listen()

	print(f"Listening on {HOST}:{PORT}...")

	while True:
		# Wait for a new client to connect and handle their connection in a new thread
		client, address = server.accept()
		print(f"New client connected: {address}")
		print("client appended")
		threading.Thread(target=handle_client, args=(client, address)).start()

def delete_request_from_database(email):
	connection = sqlite3.connect(database)
	cursor = connection.cursor()
	print(email)
	print("delete")
	cursor.execute("DELETE FROM requested WHERE email=?", (email,))
	connection.commit()
	connection.close()


if __name__ == '__main__':
	# Start the server in a separate thread
	server_thread = threading.Thread(target=start_server)
	server_thread.start()

	# Run the Flask app in the main thread
	app.run(host='0.0.0.0', port=8081)
