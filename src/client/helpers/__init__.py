import jsonschema
import json
from config.exceptions import *
from config.config import load_packet_schema, load_server_public_keys, client_store, client_store_lock
from crypto_utils.core import verify_signature, symmetric_decryption

def validate_packet_field(data, packet_type, field, seq=None, state=None):
    schema = None
    match packet_type:
        case "error":
            schema = load_packet_schema(schema_type="error_pre_auth", field=field)
            print(schema)
            # jsonschema.validate(instance=data, schema=schema)
            # raise ServerPreAuthError("Server sent an error during authentication")
            match state:
                case "pre_auth":
                    schema = load_packet_schema(schema_type="error_pre_auth", field=field)
                case "post_auth":
                    schema = load_packet_schema(schema_type="error_post_auth", field=field)
                case _:
                    raise InvalidErrorPacket("Server sent an error packet without state")
        case "cs_auth":
            schema = load_packet_schema(schema_type="cs_auth", field=field, seq=seq) 
        case "list":
            schema = load_packet_schema(schema_type="list", field=field, seq=seq) 
        case "message":
            schema = load_packet_schema(schema_type="message", field=field, seq=seq)
        case "logout":
            schema = load_packet_schema(schema_type="logout", field=field, seq=seq)
        case "cc_auth":
            schema = load_packet_schema(schema_type="cc_auth", field=field, seq=seq)
        case "incoming_message":
            schema = load_packet_schema(schema_type="incoming_message", field=field)
    jsonschema.validate(instance=data, schema=schema)

def handle_pre_auth_error(response, nonce):
    _, server_signature_verification_public_key = load_server_public_keys()
    metadata = response.get("metadata")
    validate_packet_field(metadata, packet_type="error", field="metadata", state="pre_auth")

    payload = response.get("payload")
    validate_packet_field(payload, packet_type="error", field="payload", state="pre_auth")
    signature = payload.get("signature")
    if verify_signature(f"{payload['message']}{nonce}", signature, server_signature_verification_public_key):
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
    