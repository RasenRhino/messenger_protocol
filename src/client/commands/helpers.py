import base64
import json
import socket
from client.helpers import validate_packet_field
from config.exceptions import *
from config.config import load_dh_public_params, client_store, client_store_lock, TCP_RECV_SIZE
from crypto_utils.core import *

def client_login_step_1(recipient):
    with client_store_lock:
        g = client_store["common"]["dh_public_params"]["g"]
        N = client_store["common"]["dh_public_params"]["N"]
        signature_private_key = client_store["self"]["signature_private_key"]
        recipient_epk = load_public_key_from_bytes(client_store["peers"][recipient]["encryption_public_key"])
        recipient_svpk = load_public_key_from_bytes(client_store["peers"][recipient]["signature_verification_public_key"])
        username = client_store["self"]["username"]
        listen_address = (
            client_store["peers"][recipient]["listen_address"].split(":")[0],
            int(client_store["peers"][recipient]["listen_address"].split(":")[1]),
        )
    seq = 1
    packet_type = "cc_auth"
    a = generate_dh_private_exponent()
    A = pow(g, a, N)
    signature_dh_contribution = generate_signature(f"{str(A)}{packet_type}",signature_private_key)

    payload = {
        "seq": seq,
        "sender_username": username
    }

    encrypted_payload = asymmetric_encryption(recipient_epk, json.dumps(payload).encode())
    encoded_payload = base64.b64encode(encrypted_payload).decode()
    msg = {
        "metadata": {
            "packet_type": packet_type,
            "dh_contribution": A,
            "signature_dh_contribution": signature_dh_contribution
        },
        "payload": {
            "cipher_text": encoded_payload
        }
    }

    packet = json.dumps(msg).encode()
    print(packet)
    cc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cc_socket.connect(listen_address)
    cc_socket.sendall(packet)
    
    response = cc_socket.recv(TCP_RECV_SIZE)
    response = json.loads(response.decode())
    
    packet_type = response.get("metadata").get("packet_type")
    match packet_type:
        case "cc_auth":
            metadata = response.get("metadata")
            validate_packet_field(metadata, packet_type=packet_type, field="metadata", seq=2)
            if not verify_signature(
                f"{metadata['dh_contribution']}{metadata['packet_type']}",
                metadata["signature_dh_contribution"],
                recipient_svpk
            ):
                raise InvalidSignature()
            session_key = compute_dh_key(metadata["dh_contribution"], a, N)
            with client_store_lock:
                client_store.setdefault("peers",{}).setdefault(recipient,{})["session_key"] = session_key
            payload = response.get("payload").get("cipher_text")
            decrypted_payload = symmetric_decryption(key=session_key, payload=payload, iv=metadata["iv"], tag=metadata["tag"], aad=packet_type)
            decrypted_payload = json.loads(decrypted_payload.decode())
            current_seq = decrypted_payload["seq"]
            if current_seq != 2:
                raise InvalidSeqNumber()
            validate_packet_field(decrypted_payload, packet_type=packet_type, field="payload", seq=current_seq)
            with client_store_lock:
                client_store.setdefault("peers",{}).setdefault(recipient,{})["recipient_challenge"] = decrypted_payload["recipient_challenge"]
        # Error cases need to be tweaked later
        case "error":
            pass
    

def client_login_step_2(recipient):
    pass

def initiate_client_login(recipient):
    
    client_login_step_1(recipient)
    client_login_step_2(recipient)