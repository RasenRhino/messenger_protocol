from server_models import Metadata, Payload, Message
from server_constants import PacketType, ProtocolState
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
import sqlite3, json
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

MAX_ERRORS = 3
PRIVATE_KEY_ENCRYPTION = "encryption_keys/private_key_encryption.pem"
PUBLIC_KEY_ENCRYPTION = "encryption_keys/public_key_encryption.pem" 
#sql db schema 
# username:key:salt

def parse_message(data: dict, decrypt_fn=None, key=None) -> Message:
    metadata = Metadata(**data['metadata'])
    payload_data = data['payload']
    if decrypt_fn:
        payload_data = decrypt_fn(payload_data, key)
    print(payload_data)
    payload = Payload(**payload_data)
    return Message(metadata=metadata, payload=payload)


def strip_none(obj):
    if isinstance(obj, dict):
        return {k: strip_none(v) for k, v in obj.items() if v is not None}
    elif isinstance(obj, list):
        return [strip_none(v) for v in obj if v is not None]
    return obj


class ServerProtocol(Protocol):
    def __init__(self):
        super().__init__()
        self.state_dict = {}
        self.error_count = 0

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
        cleaned = strip_none(asdict(error_msg))
        response = {"errors": {str(self.error_count): cleaned}}
        self.transport.write(json.dumps(response).encode('utf-8'))

        if self.error_count >= MAX_ERRORS:
            print(f"[!] Too many errors. Closing connection.")
            self.transport.loseConnection()

    def cs_auth_handler(self, data):
        try:
            print(data, flush=True)
            message = parse_message(data, decrypt_fn=self.asymmetric_decryption, key=self.factory.private_key)
            print(message)
        except Exception as e:
            print({e})
            print("error here")
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
            if message.payload.seq >= self.state_dict[PacketType.CS_AUTH] :
                self.send_error("Invalid sequence number", state=ProtocolState.PRE_AUTH)
                return
        match message.payload.seq : 
            case 1:
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
            self.private_key_encryption = load_private_key("encryption_keys/private_key_encryption.pem")
            self.public_key_encryption = load_public_key("encryption_keys/public_key_encryption.pem")
        except (FileNotFoundError, ValueError, TypeError) as e:
            print(f"[!] Key loading failed: {e}")
            sys.exit(1)  


def init_db():
    con = sqlite3.connect("store.db")
    cur = con.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS kv (key TEXT, value TEXT)')
    con.commit()
    con.close()


init_db()
reactor.listenTCP(9000, ServerFactory(), interface='0.0.0.0')
reactor.run()
