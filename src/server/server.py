from server_models import Metadata, Payload, Message, User
from server_constants import PacketType, ProtocolState
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
import sqlite3, json
import secrets
from dataclasses import asdict
from crypto_utils.core import *
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


def parse_message(data: dict, decrypt_fn=None, key=None, **kwargs) -> Message:
    metadata = Metadata(**data['metadata'])
    if decrypt_fn == symmetric_decryption:
        encrypted_payload = base64.b64decode(data['payload']['cipher_text'])
        iv = base64.b64decode(data['metadata']['iv'])
        tag = base64.b64decode(data['metadata']['tag'])
        aad = data['metadata']['packet_type'].encode('utf-8')
        decrypted_bytes = decrypt_fn(key, encrypted_payload, iv, tag, aad)
        payload_data = json.loads(decrypted_bytes.decode('utf-8'))
    elif decrypt_fn == asymmetric_decryption:
        payload_data = base64.b64decode(data['payload'])
        decrypted_bytes = decrypt_fn(key, payload_data)
        payload_data = json.loads(decrypted_bytes.decode('utf-8'))
    else:
        payload_data = data['payload']

    payload = Payload(**payload_data)
    return Message(metadata=metadata, payload=payload)


class ServerProtocol(Protocol):
    def __init__(self):
        super().__init__()
        self.state_dict = {}
        self.error_count = 0
        self.symmetric_key=None
        self.cs_auth_state={}
        self.username=None
    def connectionMade(self):
        self.db = sqlite3.connect("store.db")
        self.cursor = self.db.cursor()
        self.factory.numProtocols += 1
        print(f"[+] New connection. Active: {self.factory.numProtocols}")
    def connectionLost(self, reason):
        self.db.close()
        self.factory.numProtocols -= 1
        self.state_dict={}
        self.cs_auth_state = {}

        if(self.username != None and (self.username in self.factory.userlist)):
           del self.factory.userlist[self.username] 
        self.username = None
        print(f"[-] Connection lost. Active: {self.factory.numProtocols}")

    def send_error(self, message_str, state):
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
        if (self.error_count >= MAX_ERRORS or state==ProtocolState.PRE_AUTH.value):
            if(state!=ProtocolState.PRE_AUTH.value):
                print(f"[!] Too many errors. Closing connection.")
            else:
                print(f"[!] ERROR in Auth. Closing connection.")
            self.transport.loseConnection()

    def cs_auth_handler(self, data):
        try:
            if(PacketType.CS_AUTH.value not in self.state_dict.keys()):
                message = parse_message(data, decrypt_fn=asymmetric_decryption, key=self.factory.private_key)
            else:
                message = parse_message(data,decrypt_fn=symmetric_decryption,key=self.symmetric_key)
        except Exception as e:
            print(f"Exception at cs_auth_handler : {e}")
            self.send_error("Invalid message format", state=ProtocolState.PRE_AUTH.value)
            return

        if PacketType.CS_AUTH.value not in self.state_dict:
            if message.payload.seq != 1:
                self.send_error("Invalid sequence number", state=ProtocolState.PRE_AUTH.value)
                return
            self.state_dict[PacketType.CS_AUTH.value] = 1
            self.username = message.payload.username

        elif self.state_dict[PacketType.CS_AUTH.value] == 0:
            self.send_error("Already authenticated", state=ProtocolState.POST_AUTH)
        else:
            if message.payload.seq <= self.state_dict[PacketType.CS_AUTH.value] and message.payload.seq > self.state_dict[PacketType.CS_AUTH.value]+1:
                self.send_error("Invalid sequence number", state=ProtocolState.PRE_AUTH.value)
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
                            "nonce": SHA3_512(message.payload.nonce)
                        }
                        payload=json.dumps(payload)
                        cipher_text=symmetric_encryption(self.symmetric_key,payload,message.metadata.packet_type)
                        response_message = Message(
                            metadata=Metadata(
                                packet_type=PacketType.CS_AUTH.value,
                                salt=salt,
                                dh_contribution=4444, ##generate a valid_dh_contribution
                                iv=cipher_text['iv'],
                                tag=cipher_text['tag'],
                            ),
                            payload=Payload(
                                cipher_text=cipher_text['cipher_text']
                            )
                        )
                        response = message_to_dict(response_message)
                        self.transport.write(json.dumps(response).encode('utf-8'))
                        self.state_dict[PacketType.CS_AUTH.value]=2
                        return
                    else:
                        self.send_error("Username not found", state=ProtocolState.PRE_AUTH.value)
                        return
                except Exception as e:
                    print(f"[ERROR] in case 1 of cs_auth_handler : {e} ")
                    self.send_error("Something went wrong while authenting",state=ProtocolState.PRE_AUTH.value)
                    return

            case 3:
                try:
                    server_challenge_hash=SHA3_512(self.cs_auth_state['2']['server_challenge'])
                    if(server_challenge_hash != message.payload.server_challenge_solution):
                        self.send_error("Incorrect response to server challenge", state=ProtocolState.PRE_AUTH.value)
                    
                    client_challenge_solution=SHA3_512(message.payload.client_challenge)
                    payload={
                                "seq":4,
                                "client_challenge_solution":client_challenge_solution
                            }
                    payload=json.dumps(payload)
                    cipher_text=symmetric_encryption(self.symmetric_key,payload,message.metadata.packet_type)
                    response_message = Message(
                        metadata=Metadata(
                            packet_type=PacketType.CS_AUTH.value,
                            iv=cipher_text['iv'],
                            tag=cipher_text['tag'],
                        ),
                        payload=Payload(
                            cipher_text=cipher_text['cipher_text']
                        )
                    )
                    response = message_to_dict(response_message)
                    self.transport.write(json.dumps(response).encode('utf-8'))
                    self.state_dict[PacketType.CS_AUTH.value]=4
                    return
                except Exception as e:
                    print(f"[ERROR] in case 3 of cs_auth_handler : {e} ")
                    self.send_error("Something went wrong while authenting",state=ProtocolState.PRE_AUTH.value)
                    return
 
            case 5:
                try:
                    ip,port=message.payload.listening_ip.split(":")
                    self.factory.add_user_to_userlist(message.payload.username,message.payload.encryption_public_key,message.payload.signature_verification_public_key,ip,int(port))
                    #should we add any authentication messsage confirmation ?? 
                    self.state_dict[PacketType.CS_AUTH.value]=0 # 0 means authentication successful
                    print(self.factory.userlist)
                    return
                except Exception as e:
                    print(f"[ERROR] in case 5 of cs_auth_handler : {e} ")
                    self.send_error("Something went wrong while authenting",state=ProtocolState.PRE_AUTH.value)
                    
                return
            case _:
                self.send_error("Unknown sequence step", state=PacketType.CS_AUTH.value)
                return

        print(f"Received valid cs_auth packet seq={message.payload.seq}")

    def dataReceived(self, data):
        try:
            request = json.loads(data.decode('utf-8'))
            if request['metadata']['packet_type'] == PacketType.CS_AUTH.value:
                self.cs_auth_handler(request)
            else:
                self.send_error("Unsupported packet_type", state=PacketType.CS_AUTH.value)

        except Exception as e:
            print("[Exception]:", str(e))
            self.send_error("Malformed JSON or bad structure", state=PacketType.CS_AUTH.value)


class ServerFactory(Factory):
    protocol = ServerProtocol
    def __init__(self):
        self.numProtocols = 0
        self.userlist={}
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
    def add_user_to_userlist(self, username:str, enc_key:str, sign_key:str, ip:str, port:int):
        """
        Adds a user to the userlist with their encryption/signing keys and network details.

        Parameters:
        username (str): The unique identifier for the user.
        enc_key (str): The user's public key for encryption.
        sign_key (str): The user's public key for signature verification.
        ip (str): The user's IP address.
        port (int): The port on which the user is listening.
        """
        self.userlist[username] = User(
        username=username,
        encryption_public_key=enc_key,
        signing_public_key=sign_key,
        ip=ip,
        port=port
        )


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
