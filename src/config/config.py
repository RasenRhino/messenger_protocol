import json
from pathlib import Path
import threading
from crypto_utils.core import load_public_key
from config.exceptions import InvalidSchemaType

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
        with client_store_lock:
            client_store.setdefault("common",{}).setdefault("dh_public_params",{})["g"] = data["public_params"]["g"]
            client_store.setdefault("common",{}).setdefault("dh_public_params",{})["N"] = data["public_params"]["N"]
            client_store.setdefault("common",{}).setdefault("dh_public_params",{})["k"] = data["public_params"]["k"]
        return (data["public_params"]["g"], data["public_params"]["N"], data["public_params"]["k"])

def load_server_public_keys():
    return (
        load_public_key(f"{CONFIG_DIR}/encryption_keys/public_key_encryption.pem"),
        load_public_key(f"{CONFIG_DIR}/signing_keys/public_key_signing.pem")
    )

def load_packet_schema_from_file():
    with open(f"{CONFIG_DIR}/schema.json","r") as f:
        schemas = json.load(f)
    with client_store_lock:
        client_store.setdefault("common",{})["schemas"] = schemas

def load_packet_schema(schema_type, field, seq=None, state=None):
    with client_store_lock:
        schemas = client_store["common"]["schemas"]
    match schema_type:
        case "error":
            return schemas["error_schema"][state]["properties"][field]
        case "cs_auth" | "list" | "message" | "logout" | "cc_auth":
            return schemas[f"{schema_type}_schema"][str(seq)]["properties"][field]
        case "incoming_message":
            return schemas["incoming_message_schema"]["properties"][field]
        case _:
            raise InvalidSchemaType(f"schema_type: {schema_type} is not supported.")

def init_config():
    load_packet_schema_from_file()