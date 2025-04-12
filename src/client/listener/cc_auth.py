import json
import socket
import base64
from client.helpers import validate_packet_field
from config.config import client_store, client_store_lock, TCP_RECV_SIZE
from config.exceptions import *
from client.commands.commands import send_message_packet
from crypto_utils.core import *

def verify_identity(metadata, payload):
    sender_username = payload["sender_username"]
    with client_store_lock:
        cs_socket = client_store.setdefault("server",{})["socket"] 
    send_message_packet(cs_socket, sender_username, message=None, verify_identity=True)
    # Handle when username doesn't exist
    with client_store_lock:
        sender_svpk = load_public_key_from_bytes(client_store["peers"][sender_username]["signature_verification_public_key"])
    
    return verify_signature(
        f"{metadata['dh_contribution']}{metadata['packet_type']}",
        metadata["signature_dh_contribution"],
        sender_svpk
    )

def send_dh_contribution(cc_socket: socket.socket, sender_username):
    seq = 1
    packet_type = "cc_auth"
    recipient_challenge = generate_challenge()
    with client_store_lock:
        g = client_store["common"]["dh_public_params"]["g"]
        N = client_store["common"]["dh_public_params"]["N"]
        signature_private_key = client_store["self"]["signature_private_key"]
        sender_epk = load_public_key_from_bytes(client_store["peers"][sender_username]["encryption_public_key"])
        username = client_store["self"]["username"]
        client_store.setdefault("peers",{}).setdefault(sender_username,{})["recipient_challenge"] = recipient_challenge
        
    b = generate_dh_private_exponent()
    B = pow(g, b, N)
    signature_dh_contribution = generate_signature(f"{str(B)}{packet_type}",signature_private_key)

    payload = {
        "seq": seq,
        "recipient_username": username,
        "recipient_challenge": recipient_challenge
    }

    encrypted_payload = asymmetric_encryption(sender_epk, json.dumps(payload).encode())
    encoded_payload = base64.b64encode(encrypted_payload).decode()
    msg = {
        "metadata": {
            "packet_type": packet_type,
            "dh_contribution": B,
            "signature_dh_contribution": signature_dh_contribution
        },
        "payload": {
            "cipher_text": encoded_payload
        }
    }

    packet = json.dumps(msg).encode()
    print(packet)
    cc_socket.sendall(packet)

def authenticate_sender():
    pass

def handle_client_login(cc_socket):
    response = cc_socket.recv(TCP_RECV_SIZE)
    response = json.loads(response.decode())
    
    packet_type = response.get("metadata").get("packet_type")
    match packet_type:
        case "cc_auth":
            metadata = response.get("metadata")
            validate_packet_field(metadata, packet_type=packet_type, field="metadata", seq=1)
            
            with client_store_lock:
                encryption_private_key = client_store["self"]["encryption_private_key"]
            payload = response.get("payload").get("cipher_text")
            decrypted_payload = asymmetric_decryption(encryption_private_key, base64.b64decode(payload))
            decrypted_payload = json.loads(decrypted_payload.decode())
            current_seq = decrypted_payload["seq"]
            if current_seq != 1:
                raise InvalidSeqNumber()
            validate_packet_field(decrypted_payload, packet_type="cc_auth", field="payload", seq=1)
            sender_username = decrypted_payload["sender_username"]
            if not verify_identity(metadata, decrypted_payload):
                raise IdentityVerificationFailed()

            send_dh_contribution(cc_socket, sender_username)
            authenticate_sender()
           
        # Error cases need to be tweaked later
        case "error":
        #    handle_pre_auth_error(response, nonce)
            pass