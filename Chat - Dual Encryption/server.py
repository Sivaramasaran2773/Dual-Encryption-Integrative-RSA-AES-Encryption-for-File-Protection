import socket
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Cipher import PKCS1_OAEP
import threading
import tkinter as tk
import os
from tkinter import filedialog
from aes1 import main as aesmain

class ServerRSA:
    def __init__(self):
        self.bitlength = 1024
        self.private_key = None
        self.public_key = None
        self.rsa_keygen()

    def rsa_keygen(self):
        rsa_key = CryptoRSA.generate(self.bitlength)
        self.private_key = rsa_key
        self.public_key = rsa_key.publickey()

class ServerGUI:
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Chat Server")
        self.root.configure(bg="#363636")  

        text_font = ("Rockwell", 11)
        self.chat_history = tk.Text(self.root, width=60, height=20, font=text_font, bg="#363636", fg="white")  
        self.chat_history.grid(row=0, column=0, columnspan=2, pady=10)

        entry_font = ("Rockwell", 10)
        self.message_entry = tk.Text(self.root, width=50, height=2, font=entry_font, bg="#363636", fg="white")  
        self.message_entry.grid(row=1, column=0, padx=10, pady=10, columnspan=2)

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message, height=2, width=5,
                                     font=entry_font, bg="#606060", fg="white")  
        self.send_button.grid(row=2, column=0, pady=10)

        self.send_file_button = tk.Button(self.root, text="Send File", command=self.send_file, height=2,
                                          width=8, font=entry_font, bg="#606060", fg="white")  
        self.send_file_button.grid(row=2, column=1, pady=10, padx=(10, 0))

        # Bind the <Return> key to the send_message function
        self.root.bind('<Return>', lambda event=None: self.send_message())
        self.root.bind('<Shift-Return>', lambda event=None: self.send_file())

        self.root.protocol("WM_DELETE_WINDOW", self.handle_interrupt)

        self.server_rsa = ServerRSA()
        self.client_sockets = {}  # Use a dictionary to store client sockets and public keys
        self.start_server()

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("localhost", 5004))
        self.server_socket.listen(2)
        print("Server listening on port 5004")

        self.accept_thread = threading.Thread(target=self.accept_connections)
        self.accept_thread.start()

    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Accepted connection from {addr}")

            client_public_key_str = client_socket.recv(4096)
            client_rsa_key = CryptoRSA.import_key(client_public_key_str)

            # Store the client socket and public key in the dictionary
            self.client_sockets[client_socket] = client_rsa_key

            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()
        
    def handle_interrupt(self):
        print("Closing server and connected clients.")
        self.server_socket.close()

        # Close all client sockets
        for client_socket in self.client_sockets.keys():
            try:
                client_socket.close()
            except:
                pass

        # Exit the program
        os._exit(0)

    def send_message(self):
        message = self.message_entry.get("1.0", tk.END).strip()  # Get the text from the Text widget

        # Encrypt the message using each client's public key
        for client_socket, client_rsa_key in self.client_sockets.items():
            try:
                cipher = PKCS1_OAEP.new(client_rsa_key)
                encrypted_message = cipher.encrypt(message.encode())
                client_socket.send(encrypted_message)

                # Display the encrypted message in the chat history on the server side
                self.chat_history.tag_configure("server_tag", foreground="sky blue")
                self.chat_history.insert(tk.END, f"Server: {message}\n", "server_tag")
                self.chat_history.tag_add("server_tag", tk.END + "-1c", tk.END)  # Apply the tag to the last inserted line
                self.chat_history.yview(tk.END)
            except Exception as e:
                print(f"Error sending message to client: {e}")

        self.message_entry.delete("1.0", tk.END)

    def handle_client(self, client_socket):
        # Send the server's public key to the client
        client_socket.send(self.server_rsa.public_key.export_key())

        while True:
            try:
                # Process messages from the client if needed
                # For now, let's display the received messages in the GUI
                message = client_socket.recv(4096)
                if not message:
                    break
                if message == "@file".encode("utf-8"):
                    result = self.receive_file(client_socket)
                    decrypted_message = result.encode("utf-8")
                else:
                    # Decrypt the message using the server's private key
                    cipher = PKCS1_OAEP.new(self.server_rsa.private_key)
                    decrypted_message = cipher.decrypt(message)

                # Display the received message in the chat history on the server side
                self.chat_history.tag_configure("client_tag", foreground="#00FF00")
                self.chat_history.insert(tk.END, f"Client: {decrypted_message.decode()}\n", "client_tag")
                self.chat_history.tag_add("client_tag", tk.END + "-1c", tk.END)
                self.chat_history.yview(tk.END)

            except Exception as e:
                print(f"Error: {e}")
                break

        del self.client_sockets[client_socket]
        client_socket.close()

        self.restart_server()

    def restart_server(self):
        print("Restarting the server...")
        self.server_socket.close()
        self.accept_thread.join()  
        self.start_server()  

    def get_key(self):
        root = tk.Tk()
        root.withdraw()

        # Get the screen width and height
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        # Calculate the center position for the top window
        x = (screen_width - 300) // 2
        y = (screen_height - 150) // 2

        top = tk.Toplevel(root)
        top.title("AES Key Entry")

        # Set gray background color for the Toplevel window
        top.configure(bg="#808080")

        # Calculate the center position for the top window
        top.geometry(f"300x150+{x}+{y}")

        label = tk.Label(top, text="Enter the AES key:", bg="#808080", fg="white")  # Set gray background and white text
        label.pack(pady=10)  

        key_entry = tk.Entry(top, show="*", bg="white")  # Set white background for the entry widget
        key_entry.pack(pady=10) 

        show_button = tk.Button(top, text="Show Key", command=lambda: self.toggle_show(key_entry), bg="#303030", fg="white")  # Set dark mode colors for button
        show_button.pack(pady=5)

        self.show_key = False 

        def on_ok():
            nonlocal top
            self.key_value = key_entry.get()
            top.destroy()

        def on_cancel():
            nonlocal top
            self.key_value = None  
            top.destroy()

        ok_button = tk.Button(top, text="OK", command=on_ok, bg="#303030", fg="white")  # Set dark mode colors for button
        ok_button.pack(side="left", padx=10)  

        cancel_button = tk.Button(top, text="Cancel", command=on_cancel, bg="#303030", fg="white")  # Set dark mode colors for button
        cancel_button.pack(side="right", padx=10) 

        def on_key(event):
            nonlocal top
            if event.keysym == "Return":
                on_ok()
            elif event.keysym == "Escape":
                on_cancel()

        top.bind("<Key-Return>", on_key)
        top.bind("<Key-Escape>", on_key)

        key_entry.focus_set()
        root.wait_window(top)

        return self.key_value if self.key_value else None

    def toggle_show(self, entry):
        if self.show_key:
            entry.config(show="*")
            self.show_key = False
        else:
            entry.config(show="")
            self.show_key = True


    def get_file_path(self):
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(title="Select a file to send")
        return file_path
    
    def enc_send_file(self, file_path, key):
        try:
            # Get the first client socket (you may need to modify this logic based on your requirements)
            client_socket = next(iter(self.client_sockets.keys()))

            # Notify the client that a file is being sent
            client_socket.send(("@file").encode("utf-8"))

            input_file_path = file_path
            aesmain('-e', input_file_path, key)
            directory_path, file_name = os.path.split(input_file_path)
            base_name, extension = os.path.splitext(file_name)
            encrypted_file_name = f"{base_name}.aes"
            file_path = os.path.join(directory_path, encrypted_file_name).replace("\\", "/")

            file_name = os.path.basename(file_path)
            name_length = len(file_name)

            cipher = PKCS1_OAEP.new(self.client_sockets[client_socket])
            encrypted_key = cipher.encrypt(key.encode())
            client_socket.send(encrypted_key)

            client_socket.send(name_length.to_bytes(4, byteorder='big'))
            client_socket.send(file_name.encode("utf-8"))

            file_size = os.path.getsize(file_path)
            client_socket.send(file_size.to_bytes(8, byteorder='big'))

            with open(file_path, "rb") as file:
                data = file.read(1024)
                while data:
                    client_socket.send(data)
                    data = file.read(1024)

            out = f"File {file_name} sent successfully"

        except Exception as e:
            out = "Error: " + str(e)
        return out

    def send_file(self):
        key = self.get_key()
        if key is None:
            self.chat_history.insert(tk.END, "Server: File sending canceled (No AES key provided)\n")
            self.chat_history.yview(tk.END)
            return

        input_file_path = self.get_file_path()
        print(key)
        print(input_file_path)
        out = self.enc_send_file(input_file_path, key)
        self.chat_history.insert(tk.END, f"Server: {out}\n")
        self.chat_history.yview(tk.END)
        return out

    def receive_file(self, client_socket):
        try :
            enc_aes_key = client_socket.recv(1024)

            cipher = PKCS1_OAEP.new(self.server_rsa.private_key)
            aes_key = cipher.decrypt(enc_aes_key)

            destination_directory =  "C:/Users/Dell/Downloads/TestingforAES/sctesting/server"
            decrypted_aes_key_bytes = aes_key.encode('utf-8') if isinstance(aes_key, str) else aes_key

            name_length_bytes = client_socket.recv(4)
            name_length = int.from_bytes(name_length_bytes, byteorder='big')

            file_name_bytes = client_socket.recv(name_length)
            file_name = file_name_bytes.decode("utf-8")

            print(f"Receiving file: {file_name}")

            file_size_bytes = client_socket.recv(8)
            file_size = int.from_bytes(file_size_bytes, byteorder='big')

            destination_file_path = os.path.join(destination_directory, file_name)

            with open(destination_file_path, "wb") as file:
                received_size = 0
                while received_size < file_size:
                    data = client_socket.recv(1024)
                    received_size += len(data)
                    file.write(data)

            key_str = decrypted_aes_key_bytes.decode('utf-8')
            print(key_str)
            aesmain('-d', destination_file_path, key_str)

            out = (f"File {file_name} received and Decrypted successfully")
            print(out)
            print("File Decrypted Successfully and stored.")
        except Exception as e :
            out = "Error : " + str(e)
        return out

    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    server_gui = ServerGUI()
    server_gui.run()
