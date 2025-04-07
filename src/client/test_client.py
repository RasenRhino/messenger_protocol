import time
import socket
import json
import secrets
import sys
import os
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import base64
from cryptography.hazmat.primitives import hashes
from crypto_utils.core import * 
import secrets
HOST = '127.0.0.1'
PORT = 9000

# Generate nonce
nonce1 = secrets.token_hex(16)
nonce2 = secrets.token_hex(16)


# Prepare data with nonce
data = {
    "metadata": {
        "packet_type": "cs_auth"
    },
    "payload": {
        "seq": 1,
        "username": "Alice",
        "dh_contribution": 4444,
        "nonce": nonce1
    }
}

# Send to server

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #part 1
s.connect((HOST, PORT))
key=load_public_key("/Users/ridhambhagat/Documents/neu/spring2025/ns/protocol_implementation/src/server/encryption_keys/public_key_encryption.pem")
priv_key=load_private_key("/Users/ridhambhagat/Documents/neu/spring2025/ns/protocol_implementation/src/server/encryption_keys/private_key_encryption.pem")
payload_bytes=json.dumps(data['payload']).encode('utf-8')
data['payload']=base64.b64encode(asymmetric_encryption(key,payload_bytes)).decode('utf-8')
# enc_payload_bytes=base64.b64decode(data['payload'].encode('utf-8'))
# data['payload']=asymmetric_decryption(priv_key,enc_payload_bytes).decode('utf-8')
# print(data)
try:
    s.sendall(json.dumps(data).encode('utf-8'))
    response = s.recv(4096)
except Exception as e:
    print(e)

# Ritik : part 2 starts here 
response=json.loads(response.decode('utf-8'))
print("response1 :")
print(response)
time.sleep(1)
cipher_text=base64.b64decode(response['payload']['cipher_text'])
iv=base64.b64decode(response['metadata']['iv'])
tag=base64.b64decode(response['metadata']['tag']) 
aad = response['metadata']['packet_type'].encode('utf-8')
key=generate_symmetric_key(123,123,123)
plain_text=symmetric_decryption(key,cipher_text,iv,tag,aad)
recieved_payload=json.loads(plain_text.decode('utf-8'))
print(recieved_payload['nonce']==nonce1)
# cipher_text=symmetric_encryption(key,json.dumps(recieved_payload))
                                # iv=cipher_text['iv'],
                                # tag=cipher_text['tag'],
                                # associated_data=cipher_text['AAD']

# seq3 message prep

payload3={
    "seq":3,
    "server_challenge_solution": SHA3_512(recieved_payload['server_challenge']),
    "client_challenge":nonce2
}
aad_seq3='cs_auth'
cipher_text = symmetric_encryption(key,json.dumps(payload3),aad_seq3)

data2 = {
    "metadata": {
        "packet_type": "cs_auth",
        "iv" : cipher_text['iv'],
        "tag" : cipher_text['tag'],
    },
    "payload": {
        "cipher_text" : cipher_text['cipher_text']
    }
}

try:
    s.sendall(json.dumps(data2).encode('utf-8'))
    response = s.recv(4096)
    print(response)
except Exception as e:
    print(e)
