import jsonschema
from config.exceptions import *
from config.config import load_packet_schema, load_server_public_keys
from crypto_utils.core import verify_signature

def validate_packet_field(data, packet_type, field, seq=None):
    schema = None
    match packet_type:
        case "error":
            schema = load_packet_schema(schema_type="error_pre_auth", field=field)
            print(schema)
            # jsonschema.validate(instance=data, schema=schema)
            # raise ServerPreAuthError("Server sent an error during authentication")
            # case "pre_auth":
                
            #     raise ServerPreAuthError("Server sent an error during authentication")
            # case "post_auth":
            #     validate_packet(json, schema_type="error_post_auth")
            # case _:
            #     raise InvalidErrorPacket("Server sent an error packet without state")
        case "cs_auth":
            schema = load_packet_schema(schema_type="cs_auth", field=field, seq=seq) 
        case "list":
            schema = load_packet_schema(schema_type="list", field=field, seq=seq) 
        case "message":
            schema = load_packet_schema(schema_type="message", field=field, seq=seq)
        case "logout":
            schema = load_packet_schema(schema_type="logout", field=field, seq=seq)
    jsonschema.validate(instance=data, schema=schema)

def handle_pre_auth_error(response, nonce):
    _, server_signature_verification_public_key = load_server_public_keys()
    metadata = response.get("metadata")
    validate_packet_field(metadata, packet_type="error", field="metadata")

    payload = response.get("payload")
    validate_packet_field(payload, packet_type="error", field="payload")
    signature = payload.get("signature")
    if verify_signature(f"{payload['message']}{nonce}", signature, server_signature_verification_public_key):
        print("Error packet Signature Verified")
        return
    print("Signature is not valid")
    raise LogoutClient() # Change this later handle errors better.
def display_message(message):
    print(f"<- {message}")
    