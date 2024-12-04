import socket
import threading
import signal
import sys
import re  
import os
import hashlib
import base64
import struct
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAX_LEN = 200
colors = ["\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m"]
def_col = "\033[0m"

client_socket = None
exit_flag = False
server_public_key = None  # Store the server's public key
client_private_key = None  # Store the client's private key

def catch_ctrl_c(_signal, _frame):
    global exit_flag
    exit_flag = True
    str_msg = "#exit"
    try:
        encrypted_msg = encrypt_message_to_server(str_msg)
        send_encrypted_message(encrypted_msg)
    except Exception as e:
        print(f"Error while sending exit message: {e}")
    client_socket.close()
    os._exit(0)

def encrypt_message_to_server(message):
    global server_public_key
    if not server_public_key:
        print("Server public key not available. Cannot encrypt message.")
        return b''

    encrypted = server_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encode the encrypted message in Base64
    encrypted_base64 = base64.b64encode(encrypted)
    return encrypted_base64

def send_encrypted_message(encrypted_msg):
    # Send the length of the message first (4 bytes, big-endian)
    msg_length = struct.pack('>I', len(encrypted_msg))
    client_socket.sendall(msg_length + encrypted_msg)

def send_message(client_socket):
    global exit_flag
    while not exit_flag:
        try:
            msg = input(colors[1] + "You: " + def_col)
            if msg:  # Only send if the message is not empty
                encrypted_msg = encrypt_message_to_server(msg)
                send_encrypted_message(encrypted_msg)
            if msg == "#exit":
                exit_flag = True
                return
        except Exception as e:
            print(f"Error occurred while sending message: {e}")
            break

def recv_message(client_socket):
    global exit_flag
    while True:
        if exit_flag:
            return
        try:
            # Receive the length of the message first
            raw_msglen = recvall(client_socket, 4)
            if not raw_msglen:
                break
            msglen = struct.unpack('>I', raw_msglen)[0]
            # Receive the encrypted message data
            encrypted_message_base64 = recvall(client_socket, msglen)
            if not encrypted_message_base64:
                continue
            # Decrypt the message using client's private key
            msg = decrypt_message_from_server(encrypted_message_base64)
            if not msg:
                continue
            print("\033[2K\r" + msg)
            print(colors[1] + "You: " + def_col, end='', flush=True)
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def recvall(sock, n):
    # Helper function to receive n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def signup_user(client_socket):
    username = input("Enter a username: ")
    
    # Password validation loop
    while True:
        password = input("Enter a password: ")
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
        elif not re.search(r"[A-Za-z]", password):
            print("Password must contain at least one letter.")
        elif not re.search(r"\d", password):
            print("Password must contain at least one number.")
        elif not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            print("Password must contain at least one special character.")
        else:
            break  # Exit loop if password meets all criteria
    
    # Hash the password before sending
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    credentials = f"{username} {hashed_password}"

    try:
        # Encrypt the action indicator and credentials
        action_encrypted = encrypt_message_to_server('SIGNUP')
        credentials_encrypted = encrypt_message_to_server(credentials)
        
        # Send the encrypted action indicator and credentials
        send_encrypted_message(action_encrypted)
        send_encrypted_message(credentials_encrypted)
        
        # Receive and decrypt the response
        response = receive_encrypted_response()
        return response == '1'
    except Exception as e:
        print(f"An error occurred during signup: {e}")
        return False

def login_user(client_socket):
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    # Hash the password before sending
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    credentials = f"{username} {hashed_password}"

    try:
        # Encrypt the action indicator and credentials
        action_encrypted = encrypt_message_to_server('LOGIN')
        credentials_encrypted = encrypt_message_to_server(credentials)
        # Send the encrypted action indicator and credentials
        send_encrypted_message(action_encrypted)
        send_encrypted_message(credentials_encrypted)
        # Receive and decrypt the response
        response = receive_encrypted_response()
        return response == '1'
    except Exception as e:
        print(f"An error occurred during login: {e}")
        return False

def receive_encrypted_response():
    try:
        # Receive the length of the message first
        raw_msglen = recvall(client_socket, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Receive the encrypted response
        encrypted_response = recvall(client_socket, msglen)
        if not encrypted_response:
            return None
        # Decrypt the response using client's private key
        response = decrypt_message_from_server(encrypted_response)
        return response
    except Exception as e:
        print(f"Error receiving encrypted response: {e}")
        return None

def display_users(client_socket):
    # Encrypt and send the request to get the user list
    encrypted_msg = encrypt_message_to_server('GET_USERS')
    send_encrypted_message(encrypted_msg)
    # Receive the length of the message first
    raw_msglen = recvall(client_socket, 4)
    if not raw_msglen:
        print("Failed to receive user list.")
        return
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Receive the encrypted message data
    encrypted_user_list = recvall(client_socket, msglen)
    if not encrypted_user_list:
        print("Failed to receive user list.")
        return
    # Decrypt the user list
    user_list = decrypt_message_from_server(encrypted_user_list)
    if user_list:
        print(colors[4] + "\nConnected Users: " + def_col + user_list)
    else:
        print("Failed to decrypt user list.")

def receive_server_public_key():
    global server_public_key
    try:
        pem_public_key = client_socket.recv(2048)
        server_public_key = serialization.load_pem_public_key(pem_public_key)
        print("Received server public key.")
    except Exception as e:
        print(f"Failed to receive server public key: {e}")
        sys.exit()

def send_client_public_key(client_public_key):
    try:
        pem_public_key = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.sendall(pem_public_key)
        print("Sent client public key to the server.")
    except Exception as e:
        print(f"Failed to send client public key: {e}")
        sys.exit()

def decrypt_message_from_server(encrypted_message_base64):
    global client_private_key
    try:
        encrypted_message = base64.b64decode(encrypted_message_base64)
        decrypted = client_private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except Exception as e:
        print(f"Error decrypting message from server: {e}")
        return None

def main():
    global client_socket, client_private_key
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('127.0.0.1', 10000)

    try:
        print("Attempting to connect to the server...")
        client_socket.connect(server_address)
        print("Connected to the server.")
    except ConnectionRefusedError:
        print("Unable to connect to the server. Please make sure the server is running.")
        sys.exit()
    except Exception as e:
        print(f"Error occurred while connecting: {e}")
        sys.exit()

    signal.signal(signal.SIGINT, catch_ctrl_c)

    print(colors[5] + "\n\t  ====== Welcome to the chat-room ======   " + def_col)

    # Receive the server's public key
    receive_server_public_key()

    # Generate client's RSA key pair
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    client_public_key = client_private_key.public_key()

    # Send the client's public key to the server
    send_client_public_key(client_public_key)

    choice = int(input("Choose an option:\n1. Sign up\n2. Log in\nYour choice: "))

    login_success = False
    if choice == 1:
        login_success = signup_user(client_socket)
    elif choice == 2:
        login_success = login_user(client_socket)
    else:
        print("Invalid choice. Exiting...")
        client_socket.close()
        sys.exit()

    if not login_success:
        print("Operation failed. Please check your credentials or try again.")
        client_socket.close()
        sys.exit()

    display_users(client_socket)

    t_send = threading.Thread(target=send_message, args=(client_socket,))
    t_recv = threading.Thread(target=recv_message, args=(client_socket,))

    t_send.start()
    t_recv.start()

    t_send.join()
    t_recv.join()

if __name__ == "__main__":
    main()
