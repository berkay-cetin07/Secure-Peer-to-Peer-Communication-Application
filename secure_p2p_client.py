import os
import time
import base64
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import socket
import threading
import hashlib
import secrets
import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class SecureP2PClient:
    def __init__(self, root):
        self.root = root  # Main Tk window
        root.title("Secure P2P Communication Client")
        root.geometry("1200x800")  # Window size

        # Initialize all internal variables
        self.initialize_variables()

        # Build the GUI components
        self.setup_gui()

        # Ensure clean disconnect on window close
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def initialize_variables(self):
        # Networking state
        self.server_socket = None  # will hold TCP socket
        self.connected = False  # connection flag

        # User identification
        self.student_id = ""  # 5-digit student ID
        self.username = None

        # Cryptography
        self.server_enc_key = None  # RSA public key for encryption
        self.server_verify_key = None  # RSA public key for signature verification
        self.master_key = None  # symmetric key for session
        self.iv = None  # initialization vector

    def setup_gui(self):
        # Create a tabbed interface
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Main operations tab
        self.main_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="Main")
        self.create_connection_frame()  # server connect UI
        self.create_authentication_frame()  # auth UI
        self.create_message_window()  # messages log

        # Separate debug tab for diagnostic output
        self.debug_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.debug_tab, text="Debug")
        debug_frame = ttk.LabelFrame(self.debug_tab, text="Debug Window")
        debug_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.debug_text = scrolledtext.ScrolledText(debug_frame, wrap=tk.WORD)
        self.debug_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.debug_text.config(state=tk.DISABLED)

        # Status bar at bottom
        self.status_var = tk.StringVar(value="Not connected")
        ttk.Label(self.root, textvariable=self.status_var,
                  relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)

    def create_connection_frame(self):
        # Frame for server IP/port, student ID, and key file selection
        conn_frame = ttk.LabelFrame(self.main_tab, text="Server Connection")
        conn_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(conn_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip_var = tk.StringVar(value="harpoon1.sabanciuniv.edu")
        ttk.Entry(conn_frame, textvariable=self.ip_var, width=30).grid(row=0, column=1)
        ttk.Label(conn_frame, text="Server Port:").grid(row=1, column=0, sticky=tk.W)
        self.port_var = tk.StringVar(value="9999")
        ttk.Entry(conn_frame, textvariable=self.port_var, width=30).grid(row=1, column=1)
        ttk.Label(conn_frame, text="Student ID:").grid(row=2, column=0, sticky=tk.W)
        self.student_id_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.student_id_var, width=30).grid(row=2, column=1)
        # Key file selectors
        ttk.Label(conn_frame, text="Server Encryption Key:").grid(row=3, column=0, sticky=tk.W)
        self.enc_key_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.enc_key_var, width=30).grid(row=3, column=1)
        ttk.Button(conn_frame, text="Browse", command=lambda: self.load_key('enc')).grid(row=3, column=2)
        ttk.Label(conn_frame, text="Server Verification Key:").grid(row=4, column=0, sticky=tk.W)
        self.verify_key_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.verify_key_var, width=30).grid(row=4, column=1)
        ttk.Button(conn_frame, text="Browse", command=lambda: self.load_key('verify')).grid(row=4, column=2)
        # Connect button
        ttk.Button(conn_frame, text="Connect to Server", command=self.connect_to_server).grid(row=5, column=0, columnspan=3, pady=5)

    def create_authentication_frame(self):
        # UI for username input and auth controls
        auth_frame = ttk.LabelFrame(self.main_tab, text="Authentication")
        auth_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_var = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.username_var, width=30).grid(row=0, column=1)
        # Start flow, verify, delete, disconnect buttons
        btn_frame = ttk.Frame(auth_frame)
        btn_frame.grid(row=1, column=0, columnspan=2)
        ttk.Button(btn_frame, text="Start Auth Flow", command=self.start_auth).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Verify Code", command=self.verify_code).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Account", command=self.delete_account).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Disconnect", command=self.disconnect).pack(side=tk.LEFT, padx=5)
        # Email code entry
        ttk.Label(auth_frame, text="Email Code:").grid(row=2, column=0, sticky=tk.W)
        self.code_var = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.code_var, width=30).grid(row=2, column=1)

    def create_message_window(self):
        # Frame to display server and client messages
        msg_frame = ttk.LabelFrame(self.main_tab, text="Message Window")
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.message_text = scrolledtext.ScrolledText(msg_frame, wrap=tk.WORD, height=10)
        self.message_text.pack(fill=tk.BOTH, expand=True)
        self.message_text.config(state=tk.DISABLED)

    def load_key(self, key_type):
        # Open file dialog to select PEM key file
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if not filename:
            return
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            public_key = load_pem_public_key(data, backend=default_backend())
            if key_type == 'enc':
                self.server_enc_key = public_key
                self.enc_key_var.set(os.path.basename(filename))
                self.log_debug(f"Loaded encryption key: {filename}")
            else:
                self.server_verify_key = public_key
                self.verify_key_var.set(os.path.basename(filename))
                self.log_debug(f"Loaded verification key: {filename}")
        except Exception as e:
            # show error if key loading fails
            messagebox.showerror("Error", f"Failed to load key: {e}")

    def recv_signed(self):
        # Receive data, separate signature and message, verify signature
        self.log_debug("Waiting to receive signed data...")
        data = self.server_socket.recv(8192)
        if not data:
            raise ConnectionError("Server closed connection")
        sig_len = self.server_verify_key.key_size // 8  # signature length in bytes
        signature = data[:sig_len]
        message = data[sig_len:]
        self.log_debug(f"Received raw signature: {binascii.hexlify(signature)}")
        self.log_debug(f"Received raw message: {message!r}")
        # Verify signature using PKCS1v15 and SHA-256
        self.server_verify_key.verify(
            signature, message, asym_padding.PKCS1v15(), hashes.SHA256() # cryptography.exceptions.InvalidSignature exception if verification fails
        )
        self.log_debug("Signature verified successfully")
        decoded = message.decode('utf-8')  # convert bytes to string
        self.log_debug(f"Decoded message: {decoded}")
        return decoded # return decoded and succesfully verified decoded message

    def rsa_encrypt(self, plaintext: bytes) -> bytes:
        # Encrypt data with server's RSA public key using OAEP (SHA-1)
        self.log_debug("Encrypting plaintext with OAEP (SHA-1)")
        encrypted = self.server_enc_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        self.log_debug(f"Encrypted payload ({len(encrypted)} bytes)")
        return encrypted

    def connect_to_server(self):
        # Initiate TCP connection and verify keys loaded
        if self.connected:
            messagebox.showinfo("Info", "Already connected to server")
            return
        if not self.server_enc_key or not self.server_verify_key:
            messagebox.showerror("Error", "Please load both server keys first")
            return
        self.student_id = self.student_id_var.get().strip()
        # Validate student ID format
        if not (self.student_id.isdigit() and len(self.student_id) == 5):
            messagebox.showerror("Error", "Enter a valid 5-digit student ID")
            return
        try:
            ip = self.ip_var.get().strip()
            port = int(self.port_var.get())
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((ip, port))
            self.connected = True
            self.status_var.set(f"Connected to {ip}:{port}")
            self.log_message(f"✓ Connected to server at {ip}:{port}")
            self.log_debug(f"Socket connected to {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.log_debug(f"Connection error: {e}")

    def disconnect(self):
        # Cleanly close socket and update UI
        if self.connected and self.server_socket:
            try:
                self.server_socket.close()
                self.connected = False
                self.status_var.set("Disconnected")
                self.log_message("Disconnected from server")
                self.log_debug("Socket closed")
            except Exception as e:
                self.log_debug(f"Disconnect error: {e}")
                messagebox.showerror("Error", str(e))

    def start_auth(self):
        # Begin enrollment/authentication flow with server
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        self.username = self.username_var.get().strip()
        if not self.username:
            messagebox.showerror("Error", "Enter a username")
            return
        self.log_debug("Sending 'auth' command to server")
        self.server_socket.sendall(b"auth") # Send the string "auth" to the server to initiate the authentication process with the server
        msg = self.recv_signed() # Receive and verify the authenticity of the message by validating the signature
        self.log_message(f"Server: {msg}")
        # Expect success acknowledgement
        if "success" not in msg.lower():
            messagebox.showerror("Error", "Auth flow failed")
            return
        # Send concatenated student ID and username for enrollment
        enroll_payload = f"{self.student_id}{self.username}".encode()
        self.log_debug(f"Sending enroll payload: {enroll_payload!r}")
        self.server_socket.sendall(enroll_payload) # Send <ID><username> of user wishing to enroll
        msg = self.recv_signed()  # Receive and verify the authenticity of the message by validating the signature
        self.log_message(f"Server: {msg}")
        if "error" in msg.lower():
            messagebox.showerror("Error", f"Enrollment failed: {msg}")
            return
        # Request email code
        self.log_debug("Sending 'code' request to server")
        self.server_socket.sendall(b"code") # After receiving the code, the client initiates the code verification process. To begin, the client first sends the string "code" to the server
        msg = self.recv_signed() # Receive and verify the authenticity of the message by validating the signature
        self.log_message(f"Server: {msg}")
        if "success" not in msg.lower():
            messagebox.showerror("Error", "Code request failed")
            return
        messagebox.showinfo("Authentication", "Please check your email for the verification code")

    def verify_code(self):
        # Verify the code received via email
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        code = self.code_var.get().strip()
        # Validate code length
        if not code or len(code) != 6:
            messagebox.showerror("Error", "Enter the 6-digit code from email")
            return
        # Hash the code using SHA-512
        self.log_debug(f"Hashing code: {code}")
        digest = hashes.Hash(hashes.SHA512())
        digest.update(code.encode())
        code_hash = digest.finalize()
        self.log_debug(f"Code hash: {binascii.hexlify(code_hash)}")
        # Generate random master key and IV
        key_iv = secrets.token_bytes(32)
        self.master_key = key_iv[:16]
        self.iv = key_iv[16:]
        self.log_debug(f"Generated KM||IV: {binascii.hexlify(key_iv)}")
        # Encrypt KM||IV with server's public key
        encrypted_key_iv = self.rsa_encrypt(key_iv)
        # Build final payload: hash + encrypted keys + ID+username
        final_payload = code_hash + encrypted_key_iv + f"{self.student_id}{self.username}".encode()
        self.log_debug(f"Final payload length: {len(final_payload)} bytes")
        self.server_socket.sendall(final_payload)
        msg = self.recv_signed() # Receive and verify the authenticity of the message by validating the signature
        self.log_message(f"Server: {msg}")
        if "success" in msg.lower():
            # Save KM||IV to file on successful auth
            with open("session_key_iv.bin", "wb") as f:
                f.write(key_iv)
            messagebox.showinfo("Success", "Authentication successful! KM||IV saved to session_key_iv.bin")
            self.log_message("Successfully authenticated with server")
            self.log_message(f"Master Key: {self.master_key.hex()}")
            self.log_message(f"IV: {self.iv.hex()}")
        else:
            messagebox.showerror("Error", f"Authentication failed: {msg}")

    def delete_account(self):
        # Delete user account flow
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        self.username = self.username_var.get().strip()
        if not self.username:
            messagebox.showerror("Error", "Enter a username to delete")
            return
        self.log_debug("Sending 'delete' command to server")
        self.server_socket.sendall(b"delete") # Send 'delete' command to server
        msg = self.recv_signed() # Receive and verify the authenticity of the message by validating the signature
        self.log_message(f"Server: {msg}")
        if "success" not in msg.lower():
            messagebox.showerror("Error", f"Delete start failed: {msg}")
            return
        delete_payload = f"{self.student_id}{self.username}".encode()
        self.log_debug(f"Sending delete payload: {delete_payload!r}") # Send delete payloud to server in the format <ID><username>
        self.server_socket.sendall(delete_payload)
        msg = self.recv_signed() # Receive and verify the authenticity of the message by validating the signature
        self.log_message(f"Server: {msg}")
        if "success" in msg.lower():
            messagebox.showinfo("Delete", "Check email for removal code (rcode)")
            rcode = simpledialog.askstring("Removal Code", "Enter the removal code from your email:")
            if not rcode:
                return
            self.log_debug("Sending 'rcode' command to server")
            self.server_socket.sendall(b"rcode") # Send the string "rcode" to the server to initiate the verification process 
            msg = self.recv_signed() # Receive and verify the authenticity of the message by validating the signature
            self.log_message(f"Server: {msg}")
            if "success" not in msg.lower():
                messagebox.showerror("Error", f"Rcode request failed: {msg}")
                return
            final_payload = f"{rcode}{self.student_id}{self.username}".encode() 
            self.log_debug(f"Sending final delete payload: {final_payload!r}")
            self.server_socket.sendall(final_payload) # Send delete payload
            msg = self.recv_signed() # Receive and verify the authenticity of the message by validating the signature
            self.log_message(f"Server: {msg}")
            if "success" in msg.lower():
                messagebox.showinfo("Success", "Account deleted successfully!")
            else:
                messagebox.showerror("Error", f"Deletion failed: {msg}")
        else:
            messagebox.showerror("Error", f"Deletion enrollment failed: {msg}")

    def log_message(self, msg):
        # Append a line to the message window
        self.message_text.config(state=tk.NORMAL)
        self.message_text.insert(tk.END, msg + "\n")
        self.message_text.see(tk.END)
        self.message_text.config(state=tk.DISABLED)

    def log_debug(self, msg):
        # Append a line to the debug window
        self.debug_text.config(state=tk.NORMAL)
        self.debug_text.insert(tk.END, msg + "\n")
        self.debug_text.see(tk.END)
        self.debug_text.config(state=tk.DISABLED)

    def on_closing(self):
        # Ensure disconnection before quitting
        if self.connected:
            self.disconnect()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureP2PClient(root)
    root.mainloop()
