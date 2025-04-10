import base64
import json
import socket
from config.config import load_dh_public_params, client_store, client_store_lock, TCP_RECV_SIZE
from crypto_utils.core import asymmetric_encryption, generate_dh_private_exponent, generate_challenge, generate_signature

def client_login_step_1(recipient):
    with client_store_lock:
        g = client_store["common"]["dh_public_params"]["g"]
        N = client_store["common"]["dh_public_params"]["N"]
        signature_private_key = client_store["self"]["signature_private_key"]
        encryption_public_key = client_store["self"]["encryption_public_key"]
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

    encrypted_payload = asymmetric_encryption(encryption_public_key, json.dumps(payload).encode())
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
    # Might not need these, can check from local vars
    # with client_store_lock:
    #     client_store.setdefault("server",{})["cs_auth_seq"] = seq
    #     client_store.setdefault("server",{})["nonce"] = nonce
    # response = cc_socket.recv(TCP_RECV_SIZE)
    # response = json.loads(response.decode())
    # 
    # packet_type = response.get("metadata").get("packet_type")
    # match packet_type:
    #     case "cs_auth":
    #         metadata = response.get("metadata")
    #         validate_packet_field(metadata, packet_type=packet_type, field="metadata", seq=2)
    #         session_key = client_compute_srp_session_key(metadata["salt"], username, password, a, A, metadata["dh_contribution"], g, N, k)
    #         with client_store_lock:
    #             client_store.setdefault("server",{})["session_key"] = session_key
    #         payload = response.get("payload").get("cipher_text")
    #         decrypted_payload = symmetric_decryption(key=session_key, payload=payload, iv=metadata["iv"], tag=metadata["tag"], aad=packet_type)
    #         decrypted_payload = json.loads(decrypted_payload.decode())
    #         current_seq = decrypted_payload["seq"]
    #         if current_seq != 2:
    #             raise InvalidSeqNumber()
    #         validate_packet_field(decrypted_payload, packet_type="cs_auth", field="payload", seq=current_seq)
    #         if nonce != decrypted_payload["nonce"]:
    #             raise InvalidNonce()
    #         with client_store_lock:
    #             client_store.setdefault("server",{})["server_challenge"] = decrypted_payload["server_challenge"]
    #     # Error cases need to be tweaked later
    #     case "error":
    #        handle_pre_auth_error(response, nonce)
    

def client_login_step_2(recipient):
    pass

def initiate_client_login(recipient):
    
    client_login_step_1(recipient)
    client_login_step_2(recipient)