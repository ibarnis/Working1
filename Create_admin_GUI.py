import sqlite3
import tkinter as tk
from tkinter import messagebox
from tkinter import *
import whitelist
import hashlib

whitelist.main()
# Create a function to create a new admin user
def create_admin():
	whitelist.main()
	# Get the values of the username and password fields
	username = username_entry.get()
	password = password_entry.get()
	confirm_password = confirm_password_entry.get()

	# Check if the username and password fields are not empty
	if username and password and confirm_password and password == confirm_password:
		# Check if the admin user already exists in the database
		password = password.encode()
		password= hashlib.sha256(password).hexdigest()
		worked = whitelist.add_admin(username,password)
		# clear entry fields
		username_entry.delete(0, END)
		password_entry.delete(0, END)
		confirm_password_entry.delete(0, END)
		# show success message
		if worked==1:
			status_label.config(text="Admin created successfully.", fg="green")
		else:
			# show error message
			status_label.config(text="There is only one admin in this program.", fg="red")
	else:
		# show error message
		status_label.config(text="Please enter valid username and password.", fg="red")
	


# create main window
root = Tk()
root.title("Admin Creation")

# create label for instructions
instruction_label = Label(root, text="Create a new admin account:")
instruction_label.grid(row=0, column=0, columnspan=2, pady=10)

# create label and entry field for username
username_label = Label(root, text="Username:")
username_label.grid(row=1, column=0)
username_entry = Entry(root)
username_entry.grid(row=1, column=1)

# create label and entry field for password
password_label = Label(root, text="Password:")
password_label.grid(row=2, column=0)
password_entry = Entry(root, show="*")
password_entry.grid(row=2, column=1)

# create label and entry field for confirming password
confirm_password_label = Label(root, text="Confirm Password:")
confirm_password_label.grid(row=3, column=0)
confirm_password_entry = Entry(root, show="*")
confirm_password_entry.grid(row=3, column=1)

# create button for creating admin
create_admin_button = Button(root, text="Create Admin", command=create_admin)
create_admin_button.grid(row=4, column=0, columnspan=2, pady=10)

# create label for status messages
status_label = Label(root, text="")
status_label.grid(row=5, column=0, columnspan=2)

root.mainloop()