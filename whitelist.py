import sqlite3
from sqlite3 import Error
import new_rec
import numpy as np
import io
import psycopg2
from new_rec import is_match
import os
app_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(app_dir, os.pardir))

database = os.path.join(app_dir, "whiteList.db")
# the function creates conection


def create_connection(db_file):
	""" create a database connection to the SQLite database
		specified by db_file
	:param db_file: database file
	:return: Connection object or None
	"""

	conn = None
	try:
		conn = sqlite3.connect(db_file)
		# define the access rights (readable and accessible by all users, and write access by only the owner) 
		return conn
	except Error as e:
		print(e)

	return conn
#the function creates a table
def create_table(conn, create_table_sql):
	""" create a table from the create_table_sql statement
	:param conn: Connection object
	:param create_table_sql: a CREATE TABLE statement
	:return:
	"""
	try:
		c = conn.cursor()
		c.execute(create_table_sql)
	except Error as e:
		print(e)

#The function takes several inputs, including label (presumably a unique identifier for each record)
#, admin (a boolean flag indicating whether the record was created by an admin user), 
#email (the email associated with the record), 
#embedings (a set of numerical values representing the facial embeddings of the associated image), 
#and picture (the binary data of the image file).

def insertVaribleIntoTable(label, admin, email, embeddings, picture):
	try:
		conn = create_connection(database)
		cursor = conn.cursor()
		print("Connected to SQLite")

		sqlite_insert_blob_query = """ INSERT INTO requested
								  (label, admin, email, embedings, picture) 
								  VALUES (?, ?, ?, ?, ?)"""

		# convert the embeddings array to bytes
		print("embedding before insert", embeddings)
		embeddings_bytes= adapt_array(embeddings)
		
		data_tuple = (label, admin, email, embeddings_bytes, picture)
		cursor.execute(sqlite_insert_blob_query, data_tuple)
		conn.commit()
		print("Image and data inserted successfully into requested table")

		cursor.close()

	except sqlite3.Error as error:
		print("Failed to insert data into sqlite table", error)
	finally:
		if conn:
			conn.close()
			print("The SQLite connection is closed")

def add_requested_to_white():
	pass
			
def add_admin(username,password):
	worked=0
	try:
		sqliteConnection = create_connection(database)
		cursor = sqliteConnection.cursor()
		print("Connected")
		
		cursor.execute("select * from USERS")
		res = cursor.fetchall()
		if (len(res)<=0):
			sqlite_insert_with_param = """INSERT INTO USERS
							(username,password) 
							VALUES (?, ?);"""

			data_tuple = (username,password)
			cursor.execute(sqlite_insert_with_param, data_tuple)
			sqliteConnection.commit()
			print("Python Variables inserted successfully into USERS table")
			worked=1
		else:
			print("admin exists")

		cursor.close()

	except sqlite3.Error as error:
		print("Failed to insert Python variable into sqlite table", error)
	finally:
		if sqliteConnection:
			sqliteConnection.close()
			print("The SQLite connection is closed")
			return worked
			
			
def main():
	
	
	sql_create_white_table = """CREATE TABLE IF NOT EXISTS white (
										label text PRIMARY KEY,
										admin integer NOT NULL,
										email text NOT NULL,
										embedings text not null
									);"""
	sql_create_requested_table = """CREATE TABLE IF NOT EXISTS requested (
										label text PRIMARY KEY,
										admin integer NOT NULL,
										email text NOT NULL,
										embedings text not null,
										picture blob not null
									);"""									 
	sql_create_users_table = """CREATE TABLE IF NOT EXISTS USERS (
										username text PRIMARY KEY,
										password integer NOT NULL
									);"""	

	# create a database connection
	try:
		conn = create_connection(database)
		# create tasks table
		create_table(conn, sql_create_white_table)
		create_table(conn, sql_create_users_table)
		create_table(conn, sql_create_requested_table)
	except Error as e:
		print(e)
	finally:
		if conn:
			conn.close()
	
	if conn is not None:
		pass
	else:
		print("Error! cannot create the database connection.")
	return conn


def get_index(label):
	try:
		with create_connection(database) as conn, conn.cursor() as cursor:
			sqlite_select_query = """SELECT * FROM requested WHERE label = ?"""
			cursor.execute(sqlite_select_query, (label,))
			rows = cursor.fetchall()
			if len(rows) > 0:
				return rows[0][5]
			else:
				return 0
	except sqlite3.Error as error:
		print("Failed to read data from sqlite table:", error)
		return None
	except Exception as e:
		print("Error occurred:", e)
		return None
		
def get_password():
	try:
		conn = create_connection(database)
		cursor = conn.cursor()
		sqlite_select_query = """SELECT password FROM USERS"""
		cursor.execute(sqlite_select_query)
		row = cursor.fetchone()

		if row is not None and cursor.fetchone() is not None:
			return None # more than one row found, so return None
		
		if row is not None:
			return row[0]
		else:
			return None

	except sqlite3.Error as error:
		print("Failed to read data from sqlite table", error)

	finally:
		if cursor:
			cursor.close()
		if conn:
			conn.close()
			print("The SQLite connection is closed")

def get_username():
	try:
		conn = create_connection(database)
		cursor = conn.cursor()
		sqlite_select_query = """SELECT username FROM USERS"""
		cursor.execute(sqlite_select_query)
		row = cursor.fetchone()

		if row is not None and cursor.fetchone() is not None:
			return None # more than one row found, so return None
		
		if row is not None:
			return row[0]
		else:
			return None

	except sqlite3.Error as error:
		print("Failed to read data from sqlite table", error)

	finally:
		if cursor:
			cursor.close()
		if conn:
			conn.close()
			print("The SQLite connection is closed")
			
def get_all_embeddings():
	"""
	Query all rows in the white table
	:return: a list of embeddings
	"""
	conn = create_connection(database)
	cur = conn.cursor()
	cur.execute("SELECT * FROM white")
	rows = cur.fetchall()
	list_embeddings = []
	list_names=[]
	for row in rows:
		print("old: ", row[3])
		array=convert_array(row[3])
		name=(row[0])
		#array= array.flatten()
		#print("old flattened: ", array)
		list_embeddings.append(array)
		list_names.append(name)
		
	conn.close()
	return list_embeddings,list_names




def adapt_array(arr):
	"""
	http://stackoverflow.com/a/31312102/190597 (SoulNibbler)
	"""
	out = io.BytesIO()
	np.save(out, arr)
	out.seek(0)
	return sqlite3.Binary(out.read())

def convert_array(text):
	out = io.BytesIO(text)
	out.seek(0)
	return np.load(out,allow_pickle=True)
	
	
	
def read_embeddings(blob):
	# Convert the blob list to a byte string
	byte_string = bytes(blob)
	# Convert the byte string to a bytes buffer
	buffer = io.BytesIO(byte_string)
	# Load the buffer into a NumPy array with allow_pickle=True
	embeddings = np.load(buffer, allow_pickle=True)

	# Check if the embeddings array is 1-D
	if embeddings.ndim != 1:
		print("Embeddings array is not 1-D.")
		print("Embeddings array shape:", embeddings.shape)
		print("Embeddings array type:", embeddings.dtype)
		return None
	
	return embeddings


def is_white(new_embedding):
	print("new_embedding:",new_embedding)
	known_embeddings,names = get_all_embeddings()
	counter=0
	for embedding in known_embeddings:
		if embedding is None:
			continue
		
		print("embedding: ", embedding)
		print("embedding={}".format(embedding))
		print("embedding.shape: {}; len(embedding.shape): {}".format(embedding.shape, len(embedding.shape)))
		if is_match(embedding, new_embedding):
			return True,names[counter]
		counter+=1
	return False

		
if __name__ == '__main__':
	main()