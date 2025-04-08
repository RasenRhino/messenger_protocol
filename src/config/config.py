import json
from pathlib import Path
import threading
from crypto_utils.core import load_public_key
CONFIG_DIR = str(Path(__file__).parent.resolve())
TCP_RECV_SIZE = 65535

client_store = {}
client_store_lock = threading.Lock()

def load_server_address():
    with open(f"{CONFIG_DIR}/server_details.json","r") as f:
        data = json.load(f)
        return (data["server_ip"], data["server_port"])

def load_dh_public_params():
    with open(f"{CONFIG_DIR}/dh_public_params.json","r") as f:
        data = json.load(f)
        return (data["public_params"]["g"], data["public_params"]["N"], data["public_params"]["k"])

def load_server_public_key():
    return load_public_key(f"{CONFIG_DIR}/encryption_keys/public_key_encryption.pem")

def load_packet_schema(schema_type, field, seq=None):
    with open(f"{CONFIG_DIR}/schema.json","r") as f:
        schemas = json.load(f)
    match schema_type:
        case "error_pre_auth":
            return schemas["errors_schema"]["pre_auth"]["properties"][field]
        case "cs_auth":
            return schemas["cs_auth_schema"][seq]["properties"][field]
        