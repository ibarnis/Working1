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
from flask import request, abort
import threading
import time
app = Flask(__name__)
database = r"..\whiteList.db"
password_admin=""
key=""


@app.route('/loading.html')
def loading():
	message = "Look at the camera straight. Remove glasses and accessories."
	return render_template("loading.html", message=message)




@app.route('/index.html')
@app.route('/')
def hello():
	return render_template("index.html")

@app.route('/requestSent')
def requestSent():
	return render_template("requestSent.html")


@app.route('/accepted.html')



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
		
@app.route('/deny_registration', methods=['POST'])
def deny_registration():
	email = request.form.get("email")
	delete_request_from_database(email)
	return redirect(url_for("new_registration_details"))




def requires_in_white_list(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        is_in_white = int(get_in_white_list())
        if is_in_white == 1:
            print("i can enter")
            return func(*args, **kwargs)
        else:
            abort(403)    # Forbidden
    return decorated_function


@app.route('/white_space')
@requires_in_white_list
def in_white_list():
    print("in_white_list")
    return render_template('white_space.html')


@app.route('/get_in_white_list')
def get_in_white_list():
    t = threading.Thread(target=SvcDoRun().start)
    t.start()
    return 1


@app.route('/check_in_white_list', methods=['GET', 'POST'])
def check_in_white_list():
    if request.method == 'POST' and 'from_index' in request.form and request.form['from_index'] == 'true':
        return render_template('loading2.html')
    else:
        
        svc = SvcDoRun()
        svc.start()
        try:
            is_in_white = svc.is_completed()
            print("svc.is_completed() returned:", is_in_white)
        except Exception as e:
            print("Error occurred:", str(e))
            return f"Error: {str(e)}"

        # Wait for the task to complete
        while is_in_white is None:
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

def delete_request_from_database(email):
	connection = sqlite3.connect(database)
	cursor = connection.cursor()
	print(email)
	print("delete")
	cursor.execute("DELETE FROM requested WHERE email=?", (email,))
	connection.commit()
	connection.close()

if __name__ == '__main__':
	app.debug = True
	app.run(host='0.0.0.0', port = 5556)
