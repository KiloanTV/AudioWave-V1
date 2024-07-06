import socket
import threading
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

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

# Passwort und Salt festlegen (Salt sollte in der Praxis sicher gespeichert werden)
password = "mein_sicheres_passwort"
salt = b'SALTWIRDHIERGESETZT'  # In der Praxis sollte der Salt gespeichert und wiederverwendet werden

# Generiere den Schlüssel aus dem Passwort
key = generate_key_from_password(password, salt)
cipher_suite = Fernet(key)

# Server-Konfiguration
HOST = '127.0.0.1'  # localhost
PORT = 65432       # Port

# Liste der verbundenen Clients
clients = []

def broadcast(message, sender_conn):
    for client in clients:
        if client != sender_conn:
            try:
                encrypted_message = cipher_suite.encrypt(message.encode())
                client.sendall(encrypted_message)
            except Exception as e:
                print(f'Fehler beim Senden an einen Client: {e}')
                clients.remove(client)

def handle_client(conn, addr):
    print(f'Verbunden mit {addr}')
    clients.append(conn)
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                decrypted_data = cipher_suite.decrypt(data).decode()
                print(f'Empfangen von {addr}: {decrypted_data}')

                response = f'Bestätigt: {decrypted_data}'
                encrypted_response = cipher_suite.encrypt(response.encode())
                conn.sendall(encrypted_response)

                # Broadcast an alle anderen Clients
                broadcast(decrypted_data, conn)
            except Exception as e:
                print(f'Fehler bei der Verbindung mit {addr}: {e}')
                break
    clients.remove(conn)
    print(f'Verbindung mit {addr} geschlossen')

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f'Server läuft auf {HOST}:{PORT}')
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    start_server()