import client_lib  # Importiert das client_lib.py Skript

def main():
    print("Verbinden mit dem Server...")
    sock, listener_thread = client_lib.start_client()
    
    try:
        while True:
            data = input("Geben Sie die zu sendenden Daten ein (oder 'exit' zum Beenden): ")
            if data.lower() == 'exit':
                break
            client_lib.send_data(sock, data)
    finally:
        sock.close()
        listener_thread.join()

if __name__ == "__main__":
    main()