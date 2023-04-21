import tkinter as tk
from tkinter import scrolledtext
import socket
import threading

class ChatApp:
    def __init__(self, master):
        # Create the socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Initialize the GUI
        self.master = master
        self.master.title("P2P Chat")

        # Add a text box to display messages
        self.msg_box = scrolledtext.ScrolledText(self.master, state='disabled')
        self.msg_box.pack(padx=10, pady=10)

        # Add an entry field for typing messages
        self.msg_entry = tk.Entry(self.master, width=50)
        self.msg_entry.pack(padx=10, pady=10)

        # Add a "Send" button to send messages
        self.send_btn = tk.Button(self.master, text="Send", command=self.send_msg)
        self.send_btn.pack(padx=10, pady=10)

        # Add a "Quit" button to exit the chat
        self.quit_btn = tk.Button(self.master, text="Quit", command=self.quit_chat)
        self.quit_btn.pack(padx=10, pady=10)

        # Get the IP address and port number to bind the socket
        self.host = socket.gethostname()
        self.port = 9001

        # Bind the socket to the IP address and port number
        self.s.bind((self.host, self.port))

        # Listen for incoming connections
        self.s.listen(5)

        # Display a message indicating waiting for connection
        self.display_msg("Waiting for connection...")

        # Accept a connection
        self.conn, self.addr = self.s.accept()
        # Send a message indicating the connection has been established
        self.send_msg("Connected to chat server. Start chatting!")
        self.display_msg("Connected to: " + str(self.addr))

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(1)
        print(f"Listening on {self.host}:{self.port}")

        while True:
            conn, addr = sock.accept()
            threading.Thread(target=self.handle_client, args=(conn,)).start()

    def handle_client(self, conn):
        while True:
            try:
                data = conn.recv(1024).decode()
                if not data:
                    break
                print(f"Received message: {data}")
                self.display_msg(data)
            except:
                break

        print("Connection closed")
        conn.close()

    def send_msg(self):
        # Get the message to send
        msg = self.msg_entry.get()
        if not msg:
            return

        # Send the message to the other user
        self.conn.send(msg.encode('utf-8'))
        self.display_msg(msg)
        self.msg_entry.delete(0, 'end')

    def quit_chat(self):
        # Close the connection and the GUI
        self.conn.close()
        self.master.quit()

    def display_msg(self, msg):
        # Display a message in the text box
        self.msg_box.configure(state='normal')
        self.msg_box.insert(tk.END, msg + '\n')
        self.msg_box.configure(state='disabled')
        self.msg_box.yview(tk.END)


if __name__ == '__main__':
    root = tk.Tk()
    app = ChatApp(root)
    app.start()
    root.mainloop()
