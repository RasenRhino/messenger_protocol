import jsonschema
import json
from config.exceptions import *
from config.config import load_packet_schema, load_server_public_keys, client_store, client_store_lock
from crypto_utils.core import verify_signature, symmetric_decryption

def validate_packet_field(data, packet_type, field, seq=None, state=None):
    schema = None
    match packet_type:
        case "error":
            match state:
                case "pre_auth" | "post_auth":
                    schema = load_packet_schema(schema_type=packet_type, field=field, state=state)
                case _:
                    raise InvalidErrorPacket("Server sent an error packet without state")
        case "cs_auth" | "list" | "message" | "logout" | "cc_auth":
            schema = load_packet_schema(schema_type=packet_type, field=field, seq=seq)
        case "incoming_message":
            schema = load_packet_schema(schema_type="incoming_message", field=field)
        case _:
            raise InvalidPacketType(f"packet_type: {packet_type} is not supported")
    jsonschema.validate(instance=data, schema=schema)

def handle_pre_auth_error(response, nonce):
    _, server_svpk = load_server_public_keys()
    metadata = response.get("metadata")
    validate_packet_field(metadata, packet_type="error", field="metadata", state="pre_auth")

    payload = response.get("payload")
    validate_packet_field(payload, packet_type="error", field="payload", state="pre_auth")
    signature = payload.get("signature")
    if verify_signature(f"{payload['message']}{nonce}", signature, server_svpk):
        display_error(payload["message"])
    else:
        print("Signature is not valid")
    raise LogoutClient() # Change this later handle errors better.

def handle_post_auth_error(response, nonce):
    with client_store_lock:
        session_key = client_store["server"]["session_key"]
    metadata = response.get("metadata")
    validate_packet_field(metadata, packet_type="error", field="metadata", state="post_auth")
    payload = response.get("payload").get("cipher_text")
    decrypted_payload = symmetric_decryption(key=session_key, payload=payload, iv=metadata["iv"], tag=metadata["tag"], aad=metadata["packet_type"])
    decrypted_payload = json.loads(decrypted_payload.decode())
    validate_packet_field(decrypted_payload, packet_type="error", field="payload", state="post_auth")
    if nonce != decrypted_payload["nonce"]:
        raise InvalidNonce()
    display_error(decrypted_payload["message"])

def display_error(error):
    print(f"<- [ERROR]: {error}")

def display_message(message):
    print(f"<- {message}")
    