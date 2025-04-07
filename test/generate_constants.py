from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import json
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
JSON_FILE = "src/public_params.json"
SERVER_PRIVATE_PARAMS="src/server/private_params.json"
private_key = Ed25519PrivateKey.generate()
# signature = private_key.sign(b"my authenticated message")
public_key = private_key.public_key()
# public_key.verify(signature, b"my authenticated message")