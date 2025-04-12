import socket
import threading
from config.config import client_store, client_store_lock
from crypto_utils.core import generate_random_port
from client.listener.cc_auth import handle_client_login

def start_listener():
    while True:
        try:
            listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listening_port = generate_random_port()
            listen_address = ('127.0.0.1', listening_port)
            listener_socket.bind(listen_address)
            listener_socket.listen(5)
            print(f"Server listening on {listen_address}")
            break
        except socket.error:
            print(f"Failed to bind on port {listening_port}")

    try:
        listen_address = f"{listen_address[0]}:{str(listen_address[1])}"
        with client_store_lock:
            client_store.setdefault("self",{})["listen_address"] = listen_address
            # print(client_store)
        while True:
            cc_socket, client_address = listener_socket.accept()
            print(f"Accepted connection from {client_address}")
            try:
                client_thread = threading.Thread(target=handle_client_login, args=(cc_socket,), daemon=True)
                client_thread.start()
            except Exception as e:
                cc_socket.close()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        listener_socket.close()