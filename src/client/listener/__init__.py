import socket
import threading
import json
from config.config import client_store, client_store_lock, TCP_RECV_SIZE
from config.exceptions import *
from crypto_utils.core import generate_random_port
from client.listener.cc_auth import handle_client_login
from client.listener.recieve_message import handle_incoming_messages


def handle_client(cc_socket: socket.socket):
    try:
        packet = cc_socket.recv(TCP_RECV_SIZE)
        if not packet:
            raise ConnectionTerminated("Sender terminated connection")
        packet = json.loads(packet.decode())
        packet_type = packet.get("metadata").get("packet_type")
        match packet_type:
            case "cc_auth":
                handle_client_login(cc_socket, packet)
            case _:
                raise InvalidPacketType(f"Only packet_type: 'cc_auth' is allowed. Received packet_type: {packet_type}.")
    except Exception as e:
        print(f"Closing socket: {cc_socket}")
        cc_socket.close()
        print(f"[!] {threading.current_thread().name}: {type(e).__name__}: {e}")

def start_listener():
    while True:
        try:
            listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listening_port = generate_random_port()
            listen_address = ('127.0.0.1', listening_port)
            listener_socket.bind(listen_address)
            listener_socket.listen(5)
            print(f"[+] Client listening on {listen_address}")
            break
        except socket.error as e:
            print(f"[!] Failed to bind on port {listening_port}: {type(e).__name__}: {e}")

    try:
        listen_address = f"{listen_address[0]}:{str(listen_address[1])}"
        with client_store_lock:
            client_store.setdefault("self",{})["listen_address"] = listen_address
        i = 1
        while True:
            cc_socket, client_address = listener_socket.accept()
            print(f"[+] Accepted connection from {client_address}")
            try:
                client_thread = threading.Thread(target=handle_client, args=(cc_socket,), name=f"Client-{i}", daemon=True)
                client_thread.start()
                print(f"Thread for Client-{i} started")
                i += 1
            except Exception as e:
                print(f"[!] Exception: {type(e).__name__}: {e}")
    except KeyboardInterrupt:
        print("[+] Listener shutting down...")
    finally:
        listener_socket.close()