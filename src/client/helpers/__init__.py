import jsonschema
from config.exceptions import *
from config.config import load_packet_schema

def validate_packet_field(data, packet_type, field, seq=None):
    schema = None
    match packet_type:
        case "error":
            schema = load_packet_schema(schema_type="error_pre_auth", field=field)
            print(schema)
            jsonschema.validate(instance=data, schema=schema)
            raise ServerPreAuthError("Server sent an error during authentication")
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
    jsonschema.validate(instance=data, schema=schema)

def display_message(message):
    print(f"<- {message}")
    