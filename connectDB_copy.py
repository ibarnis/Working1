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
		access_rights = 0o755 
		try:
			os.chmod(db_file, access_rights)
		except OSError:
			print ("failed restricting access")
		else:
			print ("Successfully restricting access")
		return conn
	except Error as e:
		print(e)