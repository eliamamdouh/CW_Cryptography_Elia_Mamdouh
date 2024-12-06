Encrypted Chat Application
This project is a secure chat application designed to ensure confidentiality and integrity in communication. The system allows users to sign up, log in, and exchange messages in a secure environment.
It uses encryption techniques to safeguard data during transmission and storage.
The application features a client-server architecture where the server manages user authentication and communication, while the client handles message encryption and transmission.

Encryption Mechanisms
RSA Encryption: Used for exchanging public keys and securing communication between clients and the server. Messages are encrypted using the recipient's public key and decrypted with the private key.
SHA-256 Hashing: Implements secure password storage by hashing user credentials during signup and verifying them during login.
AES Encryption: Ensures the confidentiality of conversation logs by encrypting them with a derived AES key. The logs can be decrypted securely when needed.

Steps to Run the Application
Setup:
Ensure Python 3 is installed along with required libraries: cryptography, socket, and hashlib.
Save server.py and client.py in the same directory.

Start the Server:
Open a terminal and run the command:
python server.py
The server will start listening on port 10000.

Run the Client:
Open a new terminal and run the command:
python client.py
Follow the prompts to sign up or log in.

Chat:
Once logged in, you can send messages to the chatroom or view a list of connected users.
Type #exit to leave the chatroom.
