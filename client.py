import socket
import threading
import signal
import sys
import os

MAX_LEN = 200
colors = ["\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m"]
def_col = "\033[0m"

client_socket = None
exit_flag = False

def catch_ctrl_c(_signal, _frame):
    global exit_flag
    exit_flag = True
    str_msg = "#exit"
    try:
        client_socket.send(str_msg.encode())
    except Exception as e:
        print(f"Error while sending exit message: {e}")
    client_socket.close()  # Make sure to close the socket
    os._exit(0)

def send_message(client_socket):
    global exit_flag
    while not exit_flag:
        try:
            msg = input(colors[1] + "You: " + def_col)
            if msg:  # Only send if the message is not empty
                client_socket.send(msg.encode())
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
            msg = client_socket.recv(200).decode()
            if not msg:
                continue
            print("\033[2K\r" + msg)
            print(colors[1] + "You: " + def_col, end='', flush=True)
        
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def signup_user(client_socket):
    username = input("Enter a username: ")
    password = input("Enter a password: ")
    
    credentials = f"{username} {password}"
    try:
        client_socket.send(credentials.encode())
        response = client_socket.recv(2).decode()
        return response == '1'
    except ConnectionResetError:
        print("Connection was reset by the server during signup. Please try again.")
        return False
    except Exception as e:
        print(f"An error occurred during signup: {e}")
        return False

def login_user(client_socket):
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    
    credentials = f"{username} {password}"
    try:
        client_socket.send(credentials.encode())
        response = client_socket.recv(2).decode()
        return response == '1'
    except ConnectionResetError:
        print("Connection was reset by the server during login. Please try again.")
        return False
    except Exception as e:
        print(f"An error occurred during login: {e}")
        return False

def display_users(client_socket):
    client_socket.send(b'GET_USERS')
    user_list = client_socket.recv(MAX_LEN).decode()
    print(colors[4] + "\nConnected Users: " + def_col + user_list)

def main(): 
    global client_socket
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
        print("Log-in failed. Exiting...")
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
