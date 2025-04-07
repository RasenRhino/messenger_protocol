import socket
import json
import secrets
import sys
import os
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import base64
from crypto_utils.core import * 
import secrets
HOST = '127.0.0.1'
PORT = 9000

# Generate nonce
nonce = secrets.token_hex(16)

# Prepare data with nonce
data = {
    "metadata": {
        "packet_type": "cs_auth"
    },
    "payload": {
        "seq": 1,
        "username": "Alice",
        "dh_contribution": 4444,
        "nonce": nonce
    }
}

# Send to server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    key=load_public_key("/Users/ridhambhagat/Documents/neu/spring2025/ns/protocol_implementation/src/server/encryption_keys/public_key_encryption.pem")
    priv_key=load_private_key("/Users/ridhambhagat/Documents/neu/spring2025/ns/protocol_implementation/src/server/encryption_keys/private_key_encryption.pem")
    data['payload']['nonce']=secrets.token_hex(16)
    payload_bytes=json.dumps(data['payload']).encode('utf-8')
    data['payload']=base64.b64encode(asymmetric_encryption(key,payload_bytes)).decode('utf-8')
    # enc_payload_bytes=base64.b64decode(data['payload'].encode('utf-8'))
    # data['payload']=asymmetric_decryption(priv_key,enc_payload_bytes).decode('utf-8')
    # print(data)
    try:
        s.sendall(json.dumps(data).encode('utf-8'))
        response = s.recv(4096)
        print(response)
    except Exception as e:
        print(e)
