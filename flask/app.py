from flask import Flask, redirect, url_for, render_template, request
import hashlib
import sys
sys.path.append('C:/Users/User/Documents/cyber/project/working')
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


app = Flask(__name__)
database = r"C:\Users\User\Documents\cyber\project\whiteList.db"
password_admin=""
key=""


@app.route('/index.html')
@app.route('/')
def hello():
	return render_template("index.html")

@app.route('/requestSent')
def requestSent():
	return render_template("requestSent.html")

@app.route('/shoes.html')


@app.route('/Login.html')
def Login():
	return render_template("Login.html")
	
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
			Capture(name, email).capturing()
			
			return redirect('/requestSent')
	return render_template('Register.html', error=error)

	
# Route for handling the login page logic
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
	

@app.route('/admin_in')
def new_registration_details():
	# Retrieve the new registration requests from the database
	requests = get_new_registration_requests_from_database()

	# Prepare the data for each request for display in the template
	data = []
	for request in requests:
		name, email, picture_path = request[1], request[0], request[2]
		with open(picture_path, "rb" ) as image_file:
			encoded_string = base64.b64encode( image_file.read() ).decode('utf-8')
		data.append({'name': name, 'email': email, 'picture_base64': encoded_string})

	# Render the template with the requests or with an error message
	if data:
		return render_template('admin_in.html', data=data)
	else:
		return render_template('admin_in.html', message="No new registration requests found.")
	
@app.route('/deny_registration', methods=['POST'])
def deny_registration():
	email = request.form.get("email")
	delete_request_from_database(email)
	return redirect(url_for("new_registration_details"))
	


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



def generate_salt():
	salt = os.urandom(16)
	return salt

def generate_key(password, salt):
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256,
		iterations=100000,
		salt=salt,
		length=32,
		backend=default_backend()
	)
	password_bytes = password.encode()
	key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
	return key

def encrypt_folder(folder_path, password, salt):
	"""Encrypts all files in a given folder"""
	global key
	key = generate_key(password, salt)
	fernet = Fernet(key)
	for root, dirs, files in os.walk(folder_path):
		for filename in files:
			file_path = os.path.join(root, filename)
			with open(file_path, "rb") as file:
				file_data = file.read()
			encrypted_data = fernet.encrypt(file_data)
			with open(file_path, "wb") as file:
				file.write(encrypted_data)
				
def encrypt_file(file_path, password, salt):
	"""Encrypts all files in a given folder"""
	global key
	key = generate_key(password, salt)
	fernet = Fernet(key)
	with open(file_path, "rb") as file:
		file_data = file.read()
	encrypted_data = fernet.encrypt(file_data)
	with open(file_path, "wb") as file:
		file.write(encrypted_data)				  

				
@app.route('/encrypt_picture_folder', methods=['GET'])
def encrypt_picture_folder():
	salt = generate_salt()
	password =password_admin
	folder_path = "uploads"
	encrypt_folder(folder_path, password, salt)
	return 'Encryption successful', 200
	
	
def decrypt_folder(folder_path,key):
	"""Decrypts all files in a given folder"""
	
	fernet = Fernet(key)
	for root, dirs, files in os.walk(folder_path):
		for filename in files:
			file_path = os.path.join(root, filename)
			with open(file_path, "rb") as file:
				encrypted_data = file.read()
			file_data = fernet.decrypt(encrypted_data)
			with open(file_path, "wb") as file:
				file.write(file_data)



@app.route('/decrypt_picture_folder', methods=['GET'])
def decrypt_picture_folder():
	global key
	folder_path="uploads"
	print("1111111111111111")
	# Call the encrypt_data function here
	
	decrypt_folder(folder_path,key)
	# ...
	return 'Decryption successful', 200
	

@app.route('/accept_registration', methods=['POST'])
def accept_registration():
	email = request.form.get("email")
	conn = create_connection(database)
	cursor = conn.cursor()
	cursor.execute("CREATE TABLE IF NOT EXISTS white (email text, name text, picture blob)")

	sqlite_select_query = """SELECT email, name, picture FROM requested WHERE email = ?"""
	cursor.execute(sqlite_select_query, (email,))
	row = cursor.fetchone()

	if row is not None:
		cursor.execute("INSERT INTO white (email, name, picture) VALUES (?, ?, ?)", (row[0], row[1], row[2]))
		cursor.execute("DELETE FROM requested WHERE email = ?", (email,))
		conn.commit()
		conn.close()
		return "Registration accepted."
	else:
		conn.close()
		return "No registration request found for the given email address."

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

def delete_request_from_database(email):
	connection = sqlite3.connect("new_requests.db")
	cursor = connection.cursor()
	print(email)
	print("delete")
	cursor.execute("DELETE FROM new_requests WHERE email=?", (email,))
	connection.commit()
	connection.close()

if __name__ == '__main__':
	app.debug = True
	app.run(host='0.0.0.0', port = 5556)
