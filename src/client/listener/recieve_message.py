import base64
import json
import socket
from config.config import client_store, client_store_lock, TCP_RECV_SIZE
from config.exceptions import ConnectionTerminated
from client.helpers import validate_packet_field, display_message
from crypto_utils.core import symmetric_decryption


def handle_incoming_messages(cc_socket: socket.socket, sender_username):
    while True:
        packet = cc_socket.recv(TCP_RECV_SIZE)
        if not packet:
            raise ConnectionTerminated("Sender terminated connection")
        packet = json.loads(packet.decode())
        packet_type = packet.get("metadata",{}).get("packet_type")
        metadata = packet.get("metadata",{})
        validate_packet_field(metadata, packet_type="incoming_message", field="metadata")
        with client_store_lock:
            session_key = client_store["peers"][sender_username]["recieveing_session_key"]
        payload = packet.get("payload").get("cipher_text")
        decrypted_payload = symmetric_decryption(session_key, payload, metadata["iv"], metadata["tag"], aad=packet_type)
        decrypted_payload = json.loads(decrypted_payload.decode())
        validate_packet_field(decrypted_payload, packet_type="incoming_message", field="payload")
        sender_ip, sender_port = cc_socket.getpeername()
        display_message(f"<From {sender_ip}:{sender_port}:{sender_username}>:{decrypted_payload['message']}")
        