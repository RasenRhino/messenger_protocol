import socket
import json
import secrets
from ..crypto_utils import load_public_key
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
    key=load_public_key("../server/encryption_keys/public_key_encryption.pem")
    # s.sendall(json.dumps(data).encode('utf-8'))
    
    # response = s.recv(4096)
