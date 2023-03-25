from flask import Flask, request
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.form['data'].encode('utf-8')
    rsa_public_key = RSA.import_key(request.form['rsa_public_key'].encode('utf-8'))
    aes_key = AES.new(AES.key_size[-1], AES.MODE_CBC).encrypt(AES.key_size[-1] * b'\x00')
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    encrypted_data = cipher_aes.encrypt(pad(data, AES.block_size))
    iv = base64.b64encode(cipher_aes.iv).decode('utf-8')
    encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')
    encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')
    return {'data': encrypted_data, 'iv': iv, 'aes_key': encrypted_aes_key}

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.form['data'].encode('utf-8')
    iv = request.form['iv'].encode('utf-8')
    aes_key = request.form['aes_key'].encode('utf-8')
    rsa_private_key = RSA.import_key(request.form['rsa_private_key'].encode('utf-8'))
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(base64.b64decode(aes_key))
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, base64.b64decode(iv))
    decrypted_data = unpad(cipher_aes.decrypt(base64.b64decode(data)), AES.block_size)
    decrypted_data = decrypted_data.decode('utf-8')
    return {'data': decrypted_data}

@app.route('/Register.html', methods=['GET', 'POST'])
def register():
	error = None
	if request.method == 'POST':
		mail = sendMail.Mail()
		email = request.form['email']
		name = request.form['name']
		
		# Encrypt the data
		data = f'Name: {name}, Email: {email}'.encode('utf-8')
		encrypted_data = requests.post('http://localhost:5000/encrypt', data={'data': data, 'rsa_public_key': rsa_public_key}).json()

		# Send the encrypted data in the email
		mail.send(email, 'SECURED_ROOM', encrypted_data['data'])
		
		# Send notification to admin
		mail.send('barnisus@gmail.com', 'new registration', f'Name: {name}, Email: {email}, Encrypted Data: {encrypted_data}')
		
		if email == '' or name == '':
			error = 'Invalid Credentials. Please try again.'
		else:
			Capture(name, email).capturing()
			return redirect('/requestSent')
	
	return render_template('Register.html', error=error)
if __name__ == '__main__':
    app.run()