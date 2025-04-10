import json
from client.helpers import validate_packet_field
from config.config import client_store, client_store_lock, TCP_RECV_SIZE
from config.exceptions import *
from client.commands.commands import send_message_packet
from crypto_utils.core import asymmetric_decryption, verify_signature

def verify_identity(cc_socket, metadata, payload):
    sender_username = payload["sender_username"]
    send_message_packet(cc_socket, sender_username, message=None, verify_identity=True)
    with client_store_lock:
        sender_epk = client_store["peers"][sender_username]["encryption_public_key"]
        sender_svpk = client_store["peers"][sender_username]["signature_verification_public_key"]
    
    if verify_signature(
        f"{metadata["dh_contribution"]}{metadata["packet_type"]}",
        metadata["signature_dh_contribution"],
        sender_svpk
    ):
        return True

def handle_client_login(cc_socket):
    response = cc_socket.recv(TCP_RECV_SIZE)
    response = json.loads(response.decode())
    
    packet_type = response.get("metadata").get("packet_type")
    match packet_type:
        case "cc_auth":
            metadata = response.get("metadata")
            validate_packet_field(metadata, packet_type=packet_type, field="metadata", seq=2)
            
            with client_store_lock:
                encryption_private_key = client_store["self"]["encryption_private_key"]
                signature_verification_private_key = client_store["self"]["signature_verification_private_key"]
            payload = response.get("payload").get("cipher_text")
            decrypted_payload = asymmetric_decryption(encryption_private_key, payload)
            decrypted_payload = json.loads(decrypted_payload.decode())
            current_seq = decrypted_payload["seq"]
            if current_seq != 2:
                raise InvalidSeqNumber()
            validate_packet_field(decrypted_payload, packet_type="cc_auth", field="payload", seq=2)
            verify_identity(cc_socket, metadata, decrypted_payload)
           
        # Error cases need to be tweaked later
        case "error":
        #    handle_pre_auth_error(response, nonce)
            pass