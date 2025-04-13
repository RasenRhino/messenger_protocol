import json
import socket
import base64
from client.helpers import validate_packet_field
from client.listener.recieve_message import handle_incoming_messages
from config.config import client_store, client_store_lock, TCP_RECV_SIZE
from config.exceptions import *
from client.commands.commands import send_message_packet
from crypto_utils.core import *

def verify_identity(metadata, payload):
    sender_username = payload["sender_username"]
    with client_store_lock:
        cs_socket = client_store.setdefault("server",{})["socket"] 
    send_message_packet(cs_socket, sender_username, message=None, verify_identity=True)
    with client_store_lock:
        if not client_store.get("peers",{}).get(sender_username,{}).get("signature_verification_public_key"):
            raise IdentityVerificationFailed(f"Failed to Verify Identity of Sender. {sender_username} is not signed-in")
        sender_svpk = load_public_key_from_bytes(client_store["peers"][sender_username]["signature_verification_public_key"])
    
    return verify_signature(
        f"{metadata['dh_contribution']}{metadata['packet_type']}",
        metadata["signature_dh_contribution"],
        sender_svpk
    )

def send_dh_contribution(cc_socket: socket.socket, sender_username, A):
    seq = 2
    packet_type = "cc_auth"
    recipient_challenge = generate_challenge()
    
    with client_store_lock:
        g = client_store["common"]["dh_public_params"]["g"]
        N = client_store["common"]["dh_public_params"]["N"]
        signature_private_key = client_store["self"]["signature_private_key"]
        username = client_store["self"]["username"]
        client_store.setdefault("peers",{}).setdefault(sender_username,{})["recipient_challenge"] = recipient_challenge
        
    b = generate_dh_private_exponent()
    B = pow(g, b, N)
    session_key = compute_dh_key(A, b, N)
    with client_store_lock:
        client_store.setdefault("peers",{}).setdefault(sender_username,{})["recieveing_session_key"] = session_key

    signature_dh_contribution = generate_signature(f"{str(B)}{packet_type}",signature_private_key)

    payload = {
        "seq": seq,
        "recipient_username": username,
        "recipient_challenge": recipient_challenge
    }

    result = symmetric_encryption(session_key, json.dumps(payload), aad=packet_type)
    msg = {
        "metadata": {
            "packet_type": packet_type,
            "dh_contribution": B,
            "signature_dh_contribution": signature_dh_contribution,
            "iv": result["iv"],
            "tag": result["tag"]
        },
        "payload": {
            "cipher_text": result["cipher_text"]
        }
    }

    packet = json.dumps(msg).encode()
    
    cc_socket.sendall(packet)

def authenticate_sender(cc_socket, sender_username):
    response = cc_socket.recv(TCP_RECV_SIZE)
    if not response:
        raise ConnectionTerminated("Sender terminated connection")
    response = json.loads(response.decode())
    packet_type = response.get("metadata",{}).get("packet_type")
    metadata = response.get("metadata",{})
    validate_packet_field(metadata, packet_type="cc_auth", field="metadata", seq=3)
    with client_store_lock:
        session_key = client_store["peers"][sender_username]["recieveing_session_key"]
        recipient_challenge = client_store["peers"][sender_username]["recipient_challenge"]
    payload = response.get("payload").get("cipher_text")
    decrypted_payload = symmetric_decryption(key=session_key, payload=payload, iv=metadata["iv"], tag=metadata["tag"], aad=packet_type)
    decrypted_payload = json.loads(decrypted_payload.decode())
    current_seq = decrypted_payload["seq"]
    if current_seq != 3:
        raise InvalidSeqNumber("Packet Seq Number is not in order")
    validate_packet_field(decrypted_payload, packet_type="cc_auth", field="payload", seq=3)
    recipient_challenge_solution = H(recipient_challenge)
    if recipient_challenge_solution != decrypted_payload["recipient_challenge_solution"]:
        raise ChallengeResponseFailed(f"{sender_username} Failed to solve the Challenge")
    with client_store_lock:
        client_store.setdefault("peers",{}).setdefault(sender_username,{})["sender_challenge"] = decrypted_payload["sender_challenge"]

def prove_recipient(cc_socket, sender_username):
    with client_store_lock:
        session_key = client_store["peers"][sender_username]["recieveing_session_key"]
        sender_challenge = client_store["peers"][sender_username]["sender_challenge"]
    seq = 4
    packet_type = "cc_auth"
    sender_challenge_solution = H(sender_challenge)
    payload = {
        "seq": seq,
        "sender_challenge_solution": sender_challenge_solution
    }

    result = symmetric_encryption(session_key, json.dumps(payload), aad=packet_type)
    msg = {
        "metadata": {
            "packet_type": packet_type,
            "iv": result["iv"],
            "tag": result["tag"]
        },
        "payload": {
            "cipher_text": result["cipher_text"]
        }
    }

    packet = json.dumps(msg).encode()
    
    cc_socket.sendall(packet)

def handle_client_login(cc_socket, packet):
    
    metadata = packet.get("metadata")
    validate_packet_field(metadata, packet_type="cc_auth", field="metadata", seq=1)
    with client_store_lock:
        encryption_private_key = client_store["self"]["encryption_private_key"]
    payload = packet.get("payload",{}).get("cipher_text")
    decrypted_payload = asymmetric_decryption(encryption_private_key, base64.b64decode(payload))
    decrypted_payload = json.loads(decrypted_payload.decode())
    current_seq = decrypted_payload["seq"]
    if current_seq != 1:
        raise InvalidSeqNumber("Packet Seq Number is not in order")
    validate_packet_field(decrypted_payload, packet_type="cc_auth", field="payload", seq=1)
    sender_username = decrypted_payload["sender_username"]
    if not verify_identity(metadata, decrypted_payload):
        raise IdentityVerificationFailed("Failed to Verify Identity of Sender")
    
    send_dh_contribution(cc_socket, sender_username, metadata["dh_contribution"])
    authenticate_sender(cc_socket, sender_username)
    prove_recipient(cc_socket, sender_username)
    handle_incoming_messages(cc_socket, sender_username)