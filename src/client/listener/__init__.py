import socket
import threading
import json
from config.config import client_store, client_store_lock, TCP_RECV_SIZE
from config.exceptions import *
from crypto_utils.core import generate_random_port
from client.listener.cc_auth import handle_client_login
from client.listener.recieve_message import handle_incoming_messages

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip

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
    except ConnectionTerminated as e:
        cc_socket.close()
    except Exception as e:
        cc_socket.close()
        print(f"[!] Exception: {type(e).__name__}: {e}")
def start_listener():
    while True:
        try:
            listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listening_port = generate_random_port()
            listen_address = ('0.0.0.0', listening_port)
            listener_socket.bind(listen_address)
            listener_socket.listen()
            listening_ip = get_local_ip()
            print(f"[+] Client listening on {listen_address}")
            break
        except socket.error as e:
            print(f"[!] Failed to bind on port {listening_port}: {type(e).__name__}: {e}")

    try:
        listen_address = f"{listening_ip}:{str(listen_address[1])}"
        with client_store_lock:
            client_store.setdefault("self",{})["listen_address"] = listen_address
        i = 1
        while True:
            cc_socket, client_address = listener_socket.accept()
            print(f"[+] Accepted connection from {client_address}")
            try:
                client_thread = threading.Thread(target=handle_client, args=(cc_socket,), name=f"Client-{i}", daemon=True)
                client_thread.start()
                i += 1
            except Exception as e:
                print(f"[!] Exception: {type(e).__name__}: {e}")
    except KeyboardInterrupt:
        print("[+] Listener shutting down...")
    finally:
        listener_socket.close()