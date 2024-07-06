import socket
import threading
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# Funktion zur Generierung eines Schlüssels aus einem Passwort
def generate_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Passwort und derselbe Salt wie auf dem Server
password = "mein_sicheres_passwort"
salt = b'SALTWIRDHIERGESETZT'  # Der gleiche Salt wie auf dem Server

# Generiere den Schlüssel aus dem Passwort
key = generate_key_from_password(password, salt)
cipher_suite = Fernet(key)

# Server-Konfiguration
HOST = '127.0.0.1'  # Server-Adresse
PORT = 65432        # Server-Port

def listen_for_messages(sock):
    while True:
        try:
            response = sock.recv(1024)
            if response:
                decrypted_response = cipher_suite.decrypt(response).decode()
                print(f'Broadcast vom Server: {decrypted_response}')
        except Exception as e:
            print(f'Fehler beim Empfangen von Nachrichten: {e}')
            break

def send_data(sock, data):
    encrypted_data = cipher_suite.encrypt(data.encode())
    sock.sendall(encrypted_data)

def start_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    listener_thread = threading.Thread(target=listen_for_messages, args=(s,))
    listener_thread.start()
    return s, listener_thread