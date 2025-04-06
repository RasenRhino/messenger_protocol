from server_models import Metadata, Payload, Message

from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
import sqlite3, json


class ServerProtocol(Protocol):
    def __init__(self):
        super().__init__()
        self.state_dict={}
    def parse_message(data: dict) -> Message:
        metadata = Metadata(**data['metadata'])
        payload = Payload(**data['payload'])
        return Message(metadata=metadata, payload=payload)
    def connectionMade(self):
        self.db = sqlite3.connect("store.db")
        self.cursor = self.db.cursor()
        self.factory.numProtocols += 1
        print(f"[+] New connection. Active: {self.factory.numProtocols}")
    def asymmetric_decryption(self,payload,private_key): ## TODOO 
        return payload
    def cs_auth_handler(self,data):
        if('cs_auth' not in self.state_dict.keys()):
            decrypted_payload=self.asymmetric_decryption(data['payload'],self.factory.private_key)
            if(decrypted_payload['seq']!=1):
                response=
                
    def dataReceived(self, data):
        try:
            request = json.loads(data.decode('utf-8'))
            if(request['metadata']['packet_type'] == 'cs_auth'):
                self.cs_auth_handler(request)
                
            # if request.get('action') == 'insert':
            #     key = request.get('key')
            #     value = request.get('value')
            #     self.cursor.execute("INSERT INTO kv (key, value) VALUES (?, ?)", (key, value))
            #     self.db.commit()
            #     response = {'status': 'success', 'msg': f'Stored {key}:{value}'}

            # elif request.get('action') == 'get':
            #     key = request.get('key')
            #     self.cursor.execute("SELECT value FROM kv WHERE key = ?", (key,))
            #     row = self.cursor.fetchone()
            #     value = row[0] if row else None
            #     response = {'status': 'success', 'value': value}

            # elif request.get('action') == 'logout':
            #     self.transport.loseConnection()
            #     return

            else:
                response = {'status': 'error', 'msg': 'Invalid action'}

        except Exception as e:
            response = {'status': 'error', 'msg': str(e)}

        self.transport.write(json.dumps(response).encode('utf-8'))

    def connectionLost(self, reason):
        self.db.close()
        self.factory.numProtocols -= 1
        print(f"[-] Connection lost. Active: {self.factory.numProtocols}")

class ServerFactory(Factory):
    protocol = ServerProtocol
    def __init__(self):
        self.numProtocols = 0
        self.private_key = 1234 ##read from json
        self.public_key = 1234 ##read from json
# Make sure table exists
def init_db():
    con = sqlite3.connect("store.db")
    cur = con.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS kv (key TEXT, value TEXT)')
    con.commit()
    con.close()

init_db()
reactor.listenTCP(9000, ServerFactory(), interface='0.0.0.0')
reactor.run()
