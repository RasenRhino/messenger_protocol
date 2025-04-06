import socket
import json
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
    s.sendall(json.dumps(data).encode('utf-8'))

    response = s.recv(4096)
    print("Server response:", response.decode('utf-8'))

    # Logout if needed
    s.sendall(json.dumps({"action": "logout"}).encode('utf-8'))
