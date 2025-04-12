import socket
import threading
import json
from config.config import client_store, client_store_lock, TCP_RECV_SIZE
from crypto_utils.core import generate_random_port
from client.listener.cc_auth import handle_client_login
from client.listener.recieve_message import handle_incoming_messages


def handle_client(cc_socket: socket.socket):
    packet = cc_socket.recv(TCP_RECV_SIZE)
    packet = json.loads(packet.decode())
    packet_type = packet.get("metadata").get("packet_type")

    match packet_type:
        case "cc_auth":
            handle_client_login(cc_socket, packet)
        # case "incoming_message":
        #     handle_incoming_message(packet)

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
                client_thread = threading.Thread(target=handle_client, args=(cc_socket,), daemon=True)
                client_thread.start()
            except Exception as e:
                cc_socket.close()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        listener_socket.close()