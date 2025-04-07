from server_models import Metadata, Payload, Message
from server_constants import PacketType, ProtocolState
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
import sqlite3, json
import secrets
from dataclasses import asdict
from crypto_utils.core import (
    asymmetric_decryption,
    load_public_key,
    symmetric_decryption,
    symmetric_encryption,
    asymmetric_encryption,
    generate_dh_contribution,
    generate_symmetric_key,
    load_private_key
)
import sys
import base64
import signal

MAX_ERRORS = 3
PRIVATE_KEY_ENCRYPTION = "/Users/ridhambhagat/Documents/neu/spring2025/ns/protocol_implementation/src/server/encryption_keys/private_key_encryption.pem"
PUBLIC_KEY_ENCRYPTION = "/Users/ridhambhagat/Documents/neu/spring2025/ns/protocol_implementation/src/server/encryption_keys/public_key_encryption.pem" 
PUBLIC_PARAMS="/Users/ridhambhagat/Documents/neu/spring2025/ns/protocol_implementation/src/public_params.json"
def message_to_dict(message: Message) -> dict:
    return strip_none(asdict(message))


def dict_to_message(data: dict) -> Message:
    return Message(
        metadata=Metadata(**data['metadata']),
        payload=Payload(**data['payload'])
    )
def get_public_params(file):
    with open(file,'r') as f:
        return json.load(f)

def strip_none(obj):
    if isinstance(obj, dict):
        return {k: strip_none(v) for k, v in obj.items() if v is not None}
    elif isinstance(obj, list):
        return [strip_none(v) for v in obj if v is not None]
    return obj


def parse_message(data: dict, decrypt_fn=None, key=None) -> Message:
    print(data)
    metadata = Metadata(**data['metadata'])
    payload_data = data['payload']
    print("in parse message")
    payload_data = base64.b64decode(payload_data)
    if decrypt_fn:
        payload_data = json.loads(decrypt_fn(key, payload_data).decode('utf-8'))
    payload = Payload(**payload_data)
    return Message(metadata=metadata, payload=payload)


class ServerProtocol(Protocol):
    def __init__(self):
        super().__init__()
        self.state_dict = {}
        self.error_count = 0
        self.symmetric_key=None
        self.cs_auth_state={}
    def connectionMade(self):
        self.db = sqlite3.connect("store.db")
        self.cursor = self.db.cursor()
        self.factory.numProtocols += 1
        print(f"[+] New connection. Active: {self.factory.numProtocols}")

    def connectionLost(self, reason):
        self.db.close()
        self.factory.numProtocols -= 1
        print(f"[-] Connection lost. Active: {self.factory.numProtocols}")

    def send_error(self, message_str, state=ProtocolState.PRE_AUTH):
        self.error_count += 1
        error_msg = Message(
            metadata=Metadata(packet_type=PacketType.ERROR, state=state),
            payload=Payload(
                message=message_str,
                signature="Sig(message||nonce)"  # Placeholder
            )
        )
        cleaned = message_to_dict(error_msg)
        response = {"errors": {str(self.error_count): cleaned}}
        self.transport.write(json.dumps(response).encode('utf-8'))

        if self.error_count >= MAX_ERRORS:
            print(f"[!] Too many errors. Closing connection.")
            self.transport.loseConnection()

    def cs_auth_handler(self, data):
        try:
            print(data, flush=True)
            message = parse_message(data, decrypt_fn=asymmetric_decryption, key=self.factory.private_key)
            print(message)
        except Exception as e:
            print(f"Exception at cs_auth_handler : {e}")
            self.send_error("Invalid message format", state=ProtocolState.PRE_AUTH)
            return

        if PacketType.CS_AUTH not in self.state_dict:
            if message.payload.seq != 1:
                self.send_error("Invalid sequence number", state=ProtocolState.PRE_AUTH)
                return
            self.state_dict[PacketType.CS_AUTH] = 1

        elif self.state_dict[PacketType.CS_AUTH] == 0:
            self.send_error("Already authenticated", state=ProtocolState.POST_AUTH)
        else:
            if message.payload.seq <= self.state_dict[PacketType.CS_AUTH]:
                self.send_error("Invalid sequence number", state=ProtocolState.PRE_AUTH)
                return

        match message.payload.seq:
            case 1:
                try:
                    # Check if username exists
                    self.cursor.execute("SELECT * from users WHERE username=?", (message.payload.username,))
                    row = self.cursor.fetchone() ##i am wondering if i should do a fetchall and 
                    if row:
                        username,hashed_key,salt=row
                        g=self.factory.public_params['g']
                        p=self.factory.public_params['p']
                                        
                        ## Ritik : do all symmetric key bhang bhosda here, use these values. use the hashed password only

                        self.symmetric_key = generate_symmetric_key(g,p,hashed_key)
                        server_nonce = secrets.token_hex(16)  
                        self.cs_auth_state['2']={}
                        self.cs_auth_state['2']['server_challenge']=server_nonce
                        payload={
                            "seq":2,
                            "server_challenge": server_nonce,
                            "nonce": message.payload.nonce
                        }
                        payload=json.dumps(payload)
                        cipher_text=symmetric_encryption(self.symmetric_key,payload)
                    #     salt = row
                        response_message = Message(
                            metadata=Metadata(
                                packet_type=PacketType.CS_AUTH,
                                salt=salt,
                                dh_contribution=4444, ##generate a valid_dh_contribution
                                iv=cipher_text['iv'],
                                tag=cipher_text['tag'],
                                associated_data=cipher_text['AAD']
                            ),
                            payload=Payload(
                                cipher_text=cipher_text
                            )
                        )
                        response = message_to_dict(response_message)
                        self.transport.write(json.dumps(response).encode('utf-8'))
                        return
                    else:
                        self.send_error("Username not found", state=ProtocolState.PRE_AUTH)
                        return
                except Exception as e:
                    print(f"[ERROR] in case 1 of cs_auth_handler : {e} ")
                    self.send_error("Something went wrong",state=ProtocolState.PRE_AUTH)
                    return

            case 3:
                return
            case 5:
                return
            case _:
                self.send_error("Unknown sequence step", state=ProtocolState.PRE_AUTH)
                return

        print(f"Received valid cs_auth packet seq={message.payload.seq}")

    def dataReceived(self, data):
        try:
            request = json.loads(data.decode('utf-8'))
            if request['metadata']['packet_type'] == PacketType.CS_AUTH:
                self.cs_auth_handler(request)
            else:
                self.send_error("Unsupported packet_type", state=ProtocolState.PRE_AUTH)

        except Exception as e:
            print("[Exception]:", str(e))
            self.send_error("Malformed JSON or bad structure", state=ProtocolState.PRE_AUTH)


class ServerFactory(Factory):
    protocol = ServerProtocol

    def __init__(self):
        self.numProtocols = 0
        try:
            self.private_key = load_private_key(PRIVATE_KEY_ENCRYPTION)
            self.public_key_encryption = load_public_key(PUBLIC_KEY_ENCRYPTION)
            
        except Exception as e:
            print(f"[!] Key loading failed: {e}")
            sys.exit(1)
        try:
            self.public_params=get_public_params(PUBLIC_PARAMS)['public_params']
        except Exception as e:
            print(f"Couldn't get public params {e}")
            sys.exit(1)


def init_db():
    con = sqlite3.connect("store.db")
    try:
        cur = con.cursor()
    except Exception as e:
        print(f"Cannot find DB : {e}")


# Graceful shutdown

def shutdown_handler(signum, frame):
    print("\n[!] Shutting down cleanly...")
    reactor.stop()

signal.signal(signal.SIGINT, shutdown_handler)

init_db()
print("Server is listening on 0.0.0.0:9000")
reactor.listenTCP(9000, ServerFactory(), interface='0.0.0.0')
reactor.run()
