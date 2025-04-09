import sys
from pathlib import Path

ROOT_DIR = str(Path(__file__).parent.parent.resolve())
print(ROOT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)
from config.config import load_dh_public_params

import string
from server_models import Metadata, Payload, Message, User
from server_constants import PacketType, ProtocolState
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
import sqlite3, json
import secrets
from dataclasses import asdict
from crypto_utils.core import *
import base64
import signal
from config.exceptions import *
MAX_ERRORS = 3
PRIVATE_KEY_ENCRYPTION = f"{ROOT_DIR}/config/encryption_keys/private_key_encryption.pem"
PUBLIC_KEY_ENCRYPTION = f"{ROOT_DIR}/config/encryption_keys/public_key_encryption.pem" 
PRIVATE_KEY_SIGNING= f"{ROOT_DIR}/config/signing_keys/private_key_signing.pem"
PUBLIC_KEY_SIGNING= f"{ROOT_DIR}/config/signing_keys/public_key_signing.pem" 
PUBLIC_PARAMS=f"{ROOT_DIR}/public_params.json"
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
        encrypted_payload = data['payload']['cipher_text']
        iv = data['metadata']['iv']
        tag = data['metadata']['tag']
        aad = data['metadata']['packet_type']
        decrypted_bytes = decrypt_fn(key, encrypted_payload, iv, tag, aad)
        payload_data = json.loads(decrypted_bytes.decode('utf-8'))
    elif decrypt_fn == asymmetric_decryption:
        payload_data = base64.b64decode(data['payload']['cipher_text'])
        decrypted_bytes = decrypt_fn(key, payload_data)
        payload_data = json.loads(decrypted_bytes.decode('utf-8'))
    
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
        ## add a feild for final state of all state_dict entires. automatically set them to 0 when final state achieved
        if(self.username != None and (self.username in self.factory.userlist)):
           del self.factory.userlist[self.username] 
        self.username = None
        print(f"[-] Connection lost. Active: {self.factory.numProtocols}")
    def check_authentication(self):
        if(PacketType.CS_AUTH.value not in self.state_dict.keys() or self.state_dict[PacketType.CS_AUTH.value]!=0):
            return False
        return True
    def send_error(self, message_str, state=None, nonce=None):
        """Send an error message."""
        if state is None:
            state = ProtocolState.POST_AUTH.value if self.check_authentication() else ProtocolState.PRE_AUTH.value

        if nonce is None:
            nonce = generate_nonce()

        # Decide the error message format based on the state
        error_msg = self.create_error_message(message_str, state, nonce)
        if state == ProtocolState.PRE_AUTH.value:
            signature = generate_signature(f"{message_str}{nonce}",self.factory.private_key_signing)
            print(signature)
            error_msg.payload.signature=signature

        # Encrypt the message if we're in the post-auth state
        if state == ProtocolState.POST_AUTH.value:
            encrypted_msg = self.encrypt_error_message(error_msg, nonce)
            error_msg.payload.cipher_text = encrypted_msg['cipher_text']
            error_msg.metadata.iv = encrypted_msg['iv']
            error_msg.metadata.tag = encrypted_msg['tag']
            error_msg.payload.message = None
            error_msg.payload.nonce = None             
        cleaned = message_to_dict(error_msg)
        self.transport.write(json.dumps(cleaned).encode('utf-8'))

        # If there are too many errors or the state is pre-auth, close the connection
        if state == ProtocolState.PRE_AUTH.value:
            print("[!] ERROR in Auth. Closing connection.")
            self.transport.loseConnection()

    def create_error_message(self, message_str, state, nonce):
        """Create the error message structure."""
        return Message(
            metadata=Metadata(packet_type=PacketType.ERROR.value, state=state),
            payload=Payload(
                message=message_str,
                nonce=nonce,
                cipher_text=None,
                signature=None,
            )
        )

    def encrypt_error_message(self, error_msg, nonce):
        """Encrypt the error message payload."""
        error_dict = message_to_dict(error_msg)
        payload = json.dumps(error_dict['payload'])
        encrypted_payload = symmetric_encryption(self.symmetric_key, payload, error_msg.metadata.packet_type)
        return encrypted_payload


    def cs_auth_handler(self, data):
        try:
            if(PacketType.CS_AUTH.value not in self.state_dict.keys()):
                message = parse_message(data, decrypt_fn=asymmetric_decryption, key=self.factory.private_key_encryption)
            else:
                message = parse_message(data,decrypt_fn=symmetric_decryption,key=self.symmetric_key)

        except Exception as e:
            print(f"Exception at cs_auth_handler : {e}")
            self.transport.loseConnection()
            return
        if PacketType.CS_AUTH.value not in self.state_dict:
            if message.payload.seq != 1:
                self.send_error("Invalid sequence number", state=ProtocolState.PRE_AUTH.value,nonce=message.payload.nonce)
                return
            self.state_dict[PacketType.CS_AUTH.value] = 1
            self.username = message.payload.username

        elif self.state_dict[PacketType.CS_AUTH.value] == 0:
            self.send_error("Already authenticated", state=ProtocolState.POST_AUTH,nonce=message.payload.nonce)
        else:
            if message.payload.seq <= self.state_dict[PacketType.CS_AUTH.value] or message.payload.seq > self.state_dict[PacketType.CS_AUTH.value]+1:
                self.send_error("Invalid sequence number", state=ProtocolState.PRE_AUTH.value,nonce=message.payload.nonce)
                return

        match message.payload.seq:
            case 1:
                try:
                    # Check if username exists
                    self.cursor.execute("SELECT * from users WHERE username=?", (message.payload.username,))
                    row = self.cursor.fetchone() ##i am wondering if i should do a fetchall and 
                    if row:
                        username,v,salt=row
                        g=self.factory.g
                        N=self.factory.N
                        k=self.factory.k
                        A=message.metadata.dh_contribution
                        v=int(v,16)
                        B,self.symmetric_key = generate_server_key(k,v,A,g,N)
                        server_challenge = generate_challenge() 
                        self.cs_auth_state['2']={}
                        self.cs_auth_state['2']['server_challenge']=server_challenge
                        payload={
                            "seq":2,
                            "server_challenge": server_challenge,
                            "nonce": message.payload.nonce
                        }
                        payload=json.dumps(payload)
                        cipher_text=symmetric_encryption(self.symmetric_key,payload,message.metadata.packet_type)
                        response_message = Message(
                            metadata=Metadata(
                                packet_type=PacketType.CS_AUTH.value,
                                salt=salt,
                                dh_contribution=B, ##generate a valid_dh_contribution
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
                        self.send_error("Username not found", state=ProtocolState.PRE_AUTH.value,nonce=message.payload.nonce)
                        return
                except Exception as e:
                    print(f"[ERROR] in case 1 of cs_auth_handler : {e} ")
                    self.send_error("Something went wrong while authenting",nonce=message.payload.nonce)
                    return

            case 3:
                try:
                    server_challenge_hash=H(self.cs_auth_state['2']['server_challenge'])
                    if(server_challenge_hash != message.payload.server_challenge_solution):
                        self.send_error("Incorrect response to server challenge", nonce=message.payload.nonce)
                        return
                    
                    client_challenge_solution=H(message.payload.client_challenge)
                    payload={
                                "seq":4,
                                "nonce": message.payload.nonce,
                                "client_challenge_solution":client_challenge_solution
                            }
                    payload=json.dumps(payload)
                    print(payload)
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
                    self.send_error("Something went wrong while authenting",state=ProtocolState.PRE_AUTH.value,nonce=message.payload.nonce)
                    return
 
            case 5:
                #check if the payload has the required key-value pairs or not
                try:
                    print(message.payload)
                    self.factory.add_user_to_userlist(message.payload.username,message.payload.encryption_public_key,message.payload.signature_verification_public_key,message.payload.listen_address)
                    #should we add any authentication messsage confirmation ?? 
                    self.state_dict[PacketType.CS_AUTH.value]=0 # 0 means authentication successful
                    print(self.factory.userlist)
                    return
                except Exception as e:
                    print(f"[ERROR] in case 5 of cs_auth_handler : {e} ")
                    self.send_error("Something went wrong while authenting",state=ProtocolState.PRE_AUTH.value,nonce=message.payload.nonce)
                    
                return
            case _:
                self.send_error("Unknown sequence step", state=ProtocolState.PRE_AUTH.value,nonce=message.payload.nonce)
                return

    def message_handler(self,data):
        if((PacketType.CS_AUTH.value not in self.state_dict.keys()) or (self.state_dict[PacketType.CS_AUTH.value]!=0)):
            self.send_error("Not Authenticated", state=ProtocolState.POST_AUTH.value)
            return
        try:
            message = parse_message(data, decrypt_fn=symmetric_decryption, key=self.symmetric_key)
        except Exception as e:
            print(f"Exception at message handler: {e}")
            # self.send_error("Invalid message format for message request", nonce=message.payload.nonce)
            self.transport.loseConnection()
            return

        if (message.payload.recipient not in self.factory.userlist.keys()):
            self.send_error("Recipient could not be found", state=ProtocolState.POST_AUTH.value,nonce=message.payload.nonce)
            return
        match message.payload.seq:
            case 1:
                try:
                    recipient=message.payload.recipient
                    encryption_public_key = self.factory.userlist[recipient].encryption_public_key
                    signature_verification_public_key=self.factory.userlist[recipient].signing_public_key
                    listen_address=self.factory.userlist[recipient].listen_address
                    payload={
                        "seq":2,
                        "recipient":message.payload.recipient,
                        "nonce": message.payload.nonce,
                        "encryption_public_key":encryption_public_key,
                        "signature_verification_public_key":signature_verification_public_key,
                        "listen_address":listen_address
                    } 
                    payload=json.dumps(payload) 
                    cipher_text=symmetric_encryption(self.symmetric_key,payload,message.metadata.packet_type)
                    response_message=Message(
                        metadata=Metadata(
                            packet_type=PacketType.MESSAGE.value,
                            iv=cipher_text['iv'],
                            tag=cipher_text['tag'],
                        ),
                        payload=Payload(
                            cipher_text=cipher_text['cipher_text']
                        )
                    ) 
                    response = message_to_dict(response_message)
                    self.transport.write(json.dumps(response).encode('utf-8'))
                    return
                except Exception as e:
                    print(f"[ERROR] in case 1 of message_handler : {e} ")
                    self.send_error("Something went wrong with message request",nonce=message.payload.nonce)
                    return
            case _:
                self.send_error("Unknown sequence step" ,nonce=message.payload.nonce)
                return 
    def list_handler(self,data):
        if((PacketType.CS_AUTH.value not in self.state_dict.keys()) or (self.state_dict[PacketType.CS_AUTH.value]!=0)):
            self.send_error("Not Authenticated")
            return
        try:
            message = parse_message(data, decrypt_fn=symmetric_decryption, key=self.symmetric_key)
        except DecryptionFailed:
            self.transport.loseConnection()
            return
        except ServerError:
            self.transport.loseConnection()
            return
        except Exception as e:
            print(f"Exception at message handler: {e}")
            self.send_error("Invalid message format" ,nonce=message.payload.nonce)
            return
        match message.payload.seq:
            case 1:
                try:
                    list_response=self.factory.generate_user_list()
                    payload={
                        "seq" : 2,
                        "nonce" : message.payload.nonce,
                        "signed_in_users" : list_response
                    }
                    payload=json.dumps(payload)
                    cipher_text=symmetric_encryption(self.symmetric_key,payload,message.metadata.packet_type)
                    response_message=Message(
                    metadata=Metadata(
                            packet_type=PacketType.LIST.value,
                            iv=cipher_text['iv'],
                            tag=cipher_text['tag'],
                            ),
                            payload=Payload(
                                cipher_text=cipher_text['cipher_text']
                            )
                    ) 
                    response = message_to_dict(response_message)
                    self.transport.write(json.dumps(response).encode('utf-8'))
                    return
                except Exception as e:
                    print(f"[ERROR] in case 1 of list_handler: {e} ")
                    self.send_error("Something went wrong with list request",nonce=message.payload.nonce)
                    return
            case _:
                self.send_error("Unknown sequence step", nonce=message.payload.nonce)
 
        
        return
    def logout_handler(self,data):
        if((PacketType.CS_AUTH.value not in self.state_dict.keys()) or (self.state_dict[PacketType.CS_AUTH.value]!=0)):
            self.send_error("Not Authenticated")
            return
        try:
            message = parse_message(data, decrypt_fn=symmetric_decryption, key=self.symmetric_key)
        except Exception as e:
            print(f"Exception at message handler: {e}")
            # self.send_error("Invalid message format")
            self.transport.loseConnection()
            return
        match message.payload.seq:
            case 1:
                try:
                    payload={
                        "seq" : 2,
                        "nonce" : message.payload.nonce
                    }
                    payload=json.dumps(payload)
                    cipher_text=symmetric_encryption(self.symmetric_key,payload,message.metadata.packet_type)
                    response_message=Message(
                    metadata=Metadata(
                            packet_type=PacketType.LOGOUT.value,
                            iv=cipher_text['iv'],
                            tag=cipher_text['tag'],
                            ),
                            payload=Payload(
                                cipher_text=cipher_text['cipher_text']
                            )
                    )
                    response = message_to_dict(response_message)
                    self.transport.write(json.dumps(response).encode('utf-8'))
                    self.transport.loseConnection()
                    return

                except Exception as e:
                    print(f"[ERROR] in case 1 of logout_handler: {e} ")
                    self.send_error("Something went wrong with logout",nonce=message.payload.nonce)
                    return
            case _:
                self.send_error("Unknown sequence step")
                return
        return 
    def dataReceived(self, data):
        try:
            request = json.loads(data.decode('utf-8'))
            packet_type=request['metadata']['packet_type']
            if packet_type == PacketType.CS_AUTH.value:
                self.cs_auth_handler(request)
            elif packet_type == PacketType.MESSAGE.value:
                self.message_handler(request)
            elif packet_type == PacketType.LIST.value:
                self.list_handler(request)
            elif packet_type == PacketType.LOGOUT.value:
                self.logout_handler(request)
            elif packet_type == PacketType.ERROR.value:
                self.error_message_hanlder(request)
            
            else:
                self.send_error("Unsupported packet_type" )
                raise Exception

        except Exception as e:
            print("[Exception]:", str(e))
            self.send_error(f"Invalid message format : {e}" )


class ServerFactory(Factory):
    protocol = ServerProtocol
    def __init__(self):
        self.numProtocols = 0
        self.userlist={}
        # Add dummy user "Bob" with random keys and address
        random_enc_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        random_sign_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        random_ip = f"192.168.1.{secrets.randbelow(255)}:{secrets.randbelow(10000)+10000}"

        self.add_user_to_userlist(
            username="Bob",
            enc_key=random_enc_key,
            sign_key=random_sign_key,
            address=random_ip
        )

        try:
            self.private_key_encryption = load_private_key(PRIVATE_KEY_ENCRYPTION)
            # self.public_key_encryption = load_public_key(PUBLIC_KEY_ENCRYPTION)
            self.private_key_signing = load_private_key(PRIVATE_KEY_SIGNING)
            # self.public_key_signing = load_public_key(PUBLIC_KEY_SIGNING)
        except Exception as e:
            print(f"[!] Key loading failed: {e}")
            sys.exit(1)
        try:
            self.g,self.N,self.k=load_dh_public_params()
        except Exception as e:
            print(f"Couldn't get public params {e}")
            sys.exit(1)
    def add_user_to_userlist(self, username:str, enc_key:str, sign_key:str, address:str):
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
        listen_address=address,
        )
    def generate_user_list(self):
        list_response=[]
        for username in self.userlist.keys():
            list_response.append(username)
        return list_response



def init_db():
    con = sqlite3.connect("store.db")
    try:
        cur = con.cursor()
        cur.close
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
