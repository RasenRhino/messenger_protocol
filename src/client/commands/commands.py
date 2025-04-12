import json
from client.helpers import display_message
from crypto_utils.core import generate_nonce, symmetric_encryption, symmetric_decryption
from config.config import client_store, client_store_lock, TCP_RECV_SIZE
from client.helpers import validate_packet_field, handle_post_auth_error
from config.exceptions import *
from client.commands.helpers import initiate_client_login, send_message_to_recipient

def send_list_packet(cs_socket):
    seq = 1
    packet_type = "list"
    nonce = generate_nonce()
    payload = { 
        "seq": seq,
        "nonce": nonce
    }
    with client_store_lock:
        session_key = client_store["server"]["session_key"]
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
    # print(packet)
    cs_socket.sendall(packet)
    response = cs_socket.recv(TCP_RECV_SIZE)
    if not response:
        raise StopClient("Server closed the connection")
    response = json.loads(response.decode())
    packet_type = response.get("metadata").get("packet_type")
    match packet_type:
        case "list":
            metadata = response.get("metadata")
            validate_packet_field(metadata, packet_type=packet_type, field="metadata", seq=2)
            payload = response.get("payload").get("cipher_text")
            decrypted_payload = symmetric_decryption(key=session_key, payload=payload, iv=metadata["iv"], tag=metadata["tag"], aad=packet_type)
            decrypted_payload = json.loads(decrypted_payload.decode())
            current_seq = decrypted_payload["seq"]
            if current_seq != 2:
                raise InvalidSeqNumber()
            if nonce != decrypted_payload["nonce"]:
                raise InvalidNonce()
            validate_packet_field(decrypted_payload, packet_type=packet_type, field="payload", seq=current_seq)
            display_message(decrypted_payload["signed_in_users"])
            
        # Error cases need to be tweaked later
        case "error":
            handle_post_auth_error(response, nonce)
def send_message_packet(cs_socket, recipient, message, verify_identity=False):
    seq = 1
    packet_type = "message"
    nonce = generate_nonce()
    payload = { 
        "seq": seq,
        "nonce": nonce,
        "recipient": recipient
    }
    with client_store_lock:
        session_key = client_store["server"]["session_key"]
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
    # print(packet)
    cs_socket.sendall(packet)
    response = cs_socket.recv(TCP_RECV_SIZE)
    if not response:
        raise StopClient("Server closed the connection")
    response = json.loads(response.decode())
    
    packet_type = response.get("metadata").get("packet_type")
    match packet_type:
        case "message":
            metadata = response.get("metadata")
            validate_packet_field(metadata, packet_type=packet_type, field="metadata", seq=2)
            payload = response.get("payload").get("cipher_text")
            decrypted_payload = symmetric_decryption(key=session_key, payload=payload, iv=metadata["iv"], tag=metadata["tag"], aad=packet_type)
            decrypted_payload = json.loads(decrypted_payload.decode())
            current_seq = decrypted_payload["seq"]
            if current_seq != 2:
                raise InvalidSeqNumber()
            if nonce != decrypted_payload["nonce"]:
                raise InvalidNonce()
            validate_packet_field(decrypted_payload, packet_type=packet_type, field="payload", seq=current_seq)
            display_message(f"Recieved Details of {recipient}: {decrypted_payload}")
            with client_store_lock:
                client_store.setdefault("peers",{}).setdefault(recipient,{})["encryption_public_key"] = decrypted_payload["encryption_public_key"]
                client_store.setdefault("peers",{}).setdefault(recipient,{})["signature_verification_public_key"] = decrypted_payload["signature_verification_public_key"]
                client_store.setdefault("peers",{}).setdefault(recipient,{})["listen_address"] = decrypted_payload["listen_address"]
            if verify_identity:
                return
            with client_store_lock:
                client_store.setdefault("peers",{}).setdefault(recipient,{}).setdefault("message_queue",[]).append(message)
            initiate_client_login(recipient)
            send_message_to_recipient(recipient, message)
            
        # Error cases need to be tweaked later
        case "error":
           handle_post_auth_error(response, nonce)

def send_logout_packet(cs_socket):
    seq = 1
    packet_type = "logout"
    nonce = generate_nonce()
    payload = { 
        "seq": seq,
        "nonce": nonce
    }
    with client_store_lock:
        session_key = client_store["server"]["session_key"]
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
    # print(packet)
    cs_socket.sendall(packet)
    response = cs_socket.recv(TCP_RECV_SIZE)
    if not response:
        raise StopClient("Server closed the connection")
    response = json.loads(response.decode())
    
    packet_type = response.get("metadata").get("packet_type")
    match packet_type:
        case "logout":
            metadata = response.get("metadata")
            validate_packet_field(metadata, packet_type=packet_type, field="metadata", seq=2)
            payload = response.get("payload").get("cipher_text")
            decrypted_payload = symmetric_decryption(key=session_key, payload=payload, iv=metadata["iv"], tag=metadata["tag"], aad=packet_type)
            decrypted_payload = json.loads(decrypted_payload.decode())
            current_seq = decrypted_payload["seq"]
            if current_seq != 2:
                raise InvalidSeqNumber()
            if nonce != decrypted_payload["nonce"]:
                raise InvalidNonce()
            validate_packet_field(decrypted_payload, packet_type=packet_type, field="payload", seq=current_seq)
            raise LogoutClient()
            
        # Error cases need to be tweaked later
        case "error":
            metadata = response.get("metadata")
            validate_packet_field(metadata, packet_type=packet_type, field="metadata")
            payload = response.get("payload")
            validate_packet_field(payload, packet_type=packet_type, field="payload")
