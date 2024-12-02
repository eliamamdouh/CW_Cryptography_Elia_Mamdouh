import socket
import threading
import signal
import sys
import hashlib
import base64
import os
import uuid
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

# Server Configuration
MAX_LEN = 200
NUM_COLORS = 6
ENCRYPTION_PASSWORD = "PrivateConvo123"
ENCRYPTION_SALT = b"UniqueSaltHere"  # Ensure this is unique and consistent
AES_KEY_LENGTH = 32  # 256-bit AES key

# Global Variables
clients = []
conversation = []  # Stores all conversation messages
session_id = str(uuid.uuid4())  # Generate a unique session ID for this server instance
cout_lock = threading.Lock()
clients_lock = threading.Lock()

colors = ["\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m"]
def_col = "\033[0m"

# Generate RSA key pair for the server
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

class Terminal:
    """Represents a connected client."""
    def __init__(self, id, name, socket):
        self.id = id
        self.name = name
        self.socket = socket

# Utility Functions
def color(code):
    return colors[code % NUM_COLORS]

def shared_print(message, end_line=True):
    with cout_lock:
        print(message, end="\n" if end_line else "", flush=True)

def broadcast_message(message, sender_id):
    global conversation
    disconnected_clients = []

    # Add timestamp to the message
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    formatted_message = f"{timestamp} {message}"

    with clients_lock:
        for client in clients:
            if client.id != sender_id:
                try:
                    # Send length-prefixed message
                    send_length_prefixed_message(client.socket, formatted_message.encode())
                except Exception as e:
                    shared_print(f"Error sending message to client {client.id}: {e}")
                    disconnected_clients.append(client)

    # Remove disconnected clients
    with clients_lock:
        for client in disconnected_clients:
            clients.remove(client)

    # Save the formatted message to the conversation log
    conversation.append(formatted_message)

def send_length_prefixed_message(sock, data):
    # Send the length of the message first (4 bytes, big-endian)
    msg_length = struct.pack('>I', len(data))
    sock.sendall(msg_length + data)

def end_connection(id):
    with clients_lock:
        for client in clients:
            if client.id == id:
                client.socket.close()
                clients.remove(client)
                shared_print(f"Connection closed for {client.name}.")
                break

# AES Encryption/Decryption Utilities
def derive_aes_key(password, salt, length=32):
    """Derive a valid AES key of specific length (default: 32 bytes)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def pad_data(data):
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data):
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_conversation(conversation, filename):
    try:
        key = derive_aes_key(ENCRYPTION_PASSWORD, ENCRYPTION_SALT)
        validate_key_and_iv(key)

        # Pad the conversation
        padded_data = pad_data("\n".join(conversation).encode())

        # Create AES cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the conversation
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Encode the encrypted data to Base64
        encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')

        # Write Base64-encoded encrypted data to file
        with open(filename, "w") as f:
            f.write(encrypted_base64)

        return True
    except Exception as e:
        shared_print(f"Error encrypting conversation: {e}")
        return False

def decrypt_conversation(filename, output_filename):
    try:
        key = derive_aes_key(ENCRYPTION_PASSWORD, ENCRYPTION_SALT)
        validate_key_and_iv(key)

        # Read Base64-encoded encrypted data from file
        with open(filename, "r") as f:
            encrypted_base64 = f.read().strip()

        # Decode Base64 to get the encrypted data
        encrypted_data = base64.b64decode(encrypted_base64)

        # Create AES cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_data = unpad_data(padded_data).decode()

        # Write decrypted data to file
        with open(output_filename, "w") as f:
            f.write(decrypted_data)

        return True
    except Exception as e:
        shared_print(f"Error decrypting conversation: {e}")
        return False

def validate_key_and_iv(key, iv_length=16):
    """Validate AES key and IV length."""
    if len(key) not in [16, 24, 32]:
        raise ValueError(f"Invalid key size: {len(key)} bytes. Must be 16, 24, or 32 bytes.")
    if len(key[:iv_length]) != iv_length:
        raise ValueError(f"Invalid IV size: {len(key[:iv_length])} bytes. Must be {iv_length} bytes.")

def save_conversation():
    global conversation, session_id

    if not conversation:
        shared_print("No conversation to save.")
        return

    encrypted_filename = f"encrypted_conversation_{session_id}.txt"
    decrypted_filename = f"decrypted_conversation_{session_id}.txt"

    # Save encrypted conversation
    if encrypt_conversation(conversation, encrypted_filename):
        shared_print(f"Encrypted conversation saved as: {encrypted_filename}")

    # Save decrypted conversation
    try:
        with open(decrypted_filename, "w") as f:
            f.write("\n".join(conversation))
        shared_print(f"Decrypted conversation saved as: {decrypted_filename}")
    except Exception as e:
        shared_print(f"Error saving decrypted conversation: {e}")

# Signal Handling with user prompt
def handle_ctrl_c(signal_received, frame):
    shared_print("\nCTRL+C pressed. Do you want to end the server?")
    shared_print("Type 'yes' to end the server or 'no' to return to the chat.")

    choice = input("Your choice: ").strip().lower()

    if choice == 'yes':
        shared_print("Shutting down the server...")
        save_conversation()  # Save the conversation before shutting down
        with clients_lock:
            for client in clients:
                client.socket.close()  # Close all client connections
            clients.clear()

        # Ensure a clean exit
        shared_print("Server shut down successfully.")
        sys.exit(0)  # Exit the program after shutting down
    else:
        shared_print("Returning to the chat...")
        return

def decrypt_message(encrypted_message_base64):
    try:
        # Decode the Base64-encoded data
        encrypted_message = base64.b64decode(encrypted_message_base64)

        decrypted = private_key.decrypt(
            encrypted_message,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except Exception as e:
        shared_print(f"Error decrypting message: {e}")
        return None

def recvall(sock, n):
    """Helper function to receive n bytes or return None if EOF is hit."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# Client Handler
def handle_client(client_socket, id, terminal):
    rsa_successful = True  # Initialize the RSA success flag to True
    try:
        # Send the server's public key to the client
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(pem_public_key)

        # Receive credentials from the client
        credentials = client_socket.recv(MAX_LEN).decode().strip()
        if not credentials:
            shared_print(f"Received empty credentials from client {id}.")
            client_socket.send(b'0')
            return

        # Parse credentials
        try:
            name, password = credentials.split()
        except ValueError:
            shared_print(f"Invalid credentials format from client {id}.")
            client_socket.send(b'0')
            return

        shared_print(f"Received name: {name}")

        # Authenticate user
        authenticated = authenticate_user(name, password)
        if not authenticated:
            # Attempt to sign up the user
            if not signup_user(name, password):
                client_socket.send(b'0')
                return
            client_socket.send(b'1')
        else:
            client_socket.send(b'1')

        # Update the client's name in the Terminal object
        terminal.name = name  # Update the name to the authenticated username

        # Announce user join
        broadcast_message(f"{name} has joined", id)
        shared_print(color(id) + f"{name} has joined" + def_col)

        while True:
            # Read message length (4 bytes)
            raw_msglen = recvall(client_socket, 4)
            if not raw_msglen:
                break
            msglen = struct.unpack('>I', raw_msglen)[0]
            # Read the message data
            encrypted_message_base64 = recvall(client_socket, msglen)
            if not encrypted_message_base64:
                break

            # Decrypt the message
            message = decrypt_message(encrypted_message_base64)
            if not message:
                rsa_successful = False  # Set the flag to False if decryption fails
                continue  # Skip if decryption failed

            if message == "#exit":
                broadcast_message(f"{name} has left", id)
                shared_print(color(id) + f"{name} has left" + def_col)
                break  # Exit the loop to close the connection

            if message == 'GET_USERS':
                with clients_lock:
                    user_list = ', '.join(client.name for client in clients if client.name != "Anonymous")
                user_list = "People entered the chatroom: " + user_list
                try:
                    send_length_prefixed_message(client_socket, user_list.encode())
                except Exception as e:
                    shared_print(f"Error sending user list to client {id}: {e}")
                continue

            broadcast_message(f"{name}: {message}", id)
            shared_print(color(id) + f"{name}: " + def_col + message)

    except ConnectionResetError:
        shared_print(f"Connection was reset by client {name}.")
    except Exception as e:
        shared_print(f"An error occurred while handling client {name}: {e}")
    finally:
        # Ensure the connection is closed
        end_connection(id)
        # Check the RSA success flag and print the message
        if rsa_successful:
            shared_print(f"This conversation with {name} was successfully encrypted using RSA Encryption.")

# Authentication Functions
def authenticate_user(username, password):
    try:
        with open("user_credentials.txt", "r") as file:
            for line in file:
                if not line.strip():
                    continue
                user, stored_hash = line.strip().split()
                if user == username and verify_sha256(password, stored_hash):
                    return True
    except FileNotFoundError:
        shared_print("Error: User credentials file not found.")
    return False

def verify_sha256(password, stored_hash):
    """Verify if the SHA-256 hash of the password matches the stored hash."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password == stored_hash

def signup_user(username, password):
    try:
        # Check if username already exists
        if os.path.exists("user_credentials.txt"):
            with open("user_credentials.txt", "r") as file:
                for line in file:
                    if not line.strip():
                        continue
                    existing_user = line.strip().split()[0]
                    if username == existing_user:
                        shared_print("Error: Username already exists.")
                        return False

        # Hash the password and store credentials
        hashed_password = hashlib.sha256(password.encode()).hexdigest()  # SHA-256 hash
        with open("user_credentials.txt", "a") as file:
            file.write(f"{username} {hashed_password}\n")
            return True

    except IOError as e:
        shared_print(f"Error: Unable to open file: {e}")
        return False

def main():
    global session_id

    # Print the welcome message
    print(colors[5] + "\n\t  ====== Welcome to the chat-room ======   " + def_col)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 10000))
    server_socket.listen(8)

    signal.signal(signal.SIGINT, handle_ctrl_c)

    print(f"Server is running. Session ID: {session_id}")

    while True:
        try:
            client_socket, client_addr = server_socket.accept()
            id = len(clients)
            client_name = f"Client_{id}"

            shared_print(f"Connection accepted from {client_addr}.")

            terminal = Terminal(id, client_name, client_socket)
            with clients_lock:
                clients.append(terminal)

            # Pass the terminal object to handle_client
            threading.Thread(target=handle_client, args=(client_socket, id, terminal), daemon=True).start()
        except Exception as e:
            shared_print(f"Error accepting connection: {e}")
            break

if __name__ == "__main__":
    main()
