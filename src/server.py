from server_models import Metadata, Payload, Message
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
import sqlite3, json
from dataclasses import asdict

MAX_ERRORS = 3

def parse_message(data: dict) -> Message:
    metadata = Metadata(**data['metadata'])
    payload = Payload(**data['payload'])
    return Message(metadata=metadata, payload=payload)


class ServerProtocol(Protocol):
    def __init__(self):
        super().__init__()
        self.state_dict = {}
        self.error_count = 0  # Track number of protocol-level errors

    def connectionMade(self):
        self.db = sqlite3.connect("store.db")
        self.cursor = self.db.cursor()
        self.factory.numProtocols += 1
        print(f"[+] New connection. Active: {self.factory.numProtocols}")

    def connectionLost(self, reason):
        self.db.close()
        self.factory.numProtocols -= 1
        print(f"[-] Connection lost. Active: {self.factory.numProtocols}")

    def asymmetric_decryption(self, payload, private_key):  # Placeholder
        return payload

    def send_error(self, message_str, state="pre-auth"):
        """Unified error response + error count tracking"""
        self.error_count += 1

        error_msg = Message(
            metadata=Metadata(packet_type="error", state=state),
            payload=Payload(
                message=message_str,
                signature="Sig(message||nonce)"  # Placeholder, static for now
            )
        )
        response = {"errors": {str(self.error_count): asdict(error_msg)}}
        self.transport.write(json.dumps(response).encode('utf-8'))

        if self.error_count >= MAX_ERRORS:
            print(f"[!] Too many errors. Closing connection.")
            self.transport.loseConnection()

    def cs_auth_handler(self, data):
        if 'cs_auth' not in self.state_dict:
            try:
                decrypted_payload = self.asymmetric_decryption(data['payload'], self.factory.private_key)
                message = Message(
                    metadata=Metadata(**data['metadata']),
                    payload=Payload(**decrypted_payload)
                )

                if message.payload.seq != 1:
                    self.send_error("Invalid sequence number", state="pre-auth")
                    return

                self.state_dict['cs_auth'] = {
                    "username": message.payload.username,
                    "nonce": message.payload.nonce,
                    "dh_contribution": message.payload.dh_contribution
                }
                success = {
                    "status": "success",
                    "msg": "cs_auth successful"
                }
                self.transport.write(json.dumps(success).encode('utf-8'))

            except Exception:
                self.send_error("Invalid message format", state="pre-auth")

    def dataReceived(self, data):
        try:
            request = json.loads(data.decode('utf-8'))

            if request['metadata']['packet_type'] == 'cs_auth':
                self.cs_auth_handler(request)
            else:
                self.send_error("Unsupported packet_type", state="pre-auth")

        except Exception:
            self.send_error("Malformed JSON or bad structure", state="pre-auth")


class ServerFactory(Factory):
    protocol = ServerProtocol

    def __init__(self):
        self.numProtocols = 0
        self.private_key = 1234  # Placeholder
        self.public_key = 1234


def init_db():
    con = sqlite3.connect("store.db")
    cur = con.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS kv (key TEXT, value TEXT)')
    con.commit()
    con.close()


init_db()
reactor.listenTCP(9000, ServerFactory(), interface='0.0.0.0')
reactor.run()
