from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
import sqlite3

class ServerProtocol(Protocol):
    def connectionMade(self):
        self.factory.numProtocols += 1
        print(f"[+] New connection. Active: {self.factory.numProtocols}")

    def dataReceived(self, data):
        self.transport.write(data)

    def connectionLost(self, reason):
        self.factory.numProtocols -= 1
        print(f"[-] Connection lost. Active: {self.factory.numProtocols}")
    
class ServerFactory(Factory):
    protocol = ServerProtocol 
    con = sqlite3.connect("store.db")
    def __init__(self):
        self.numProtocols = 0 
        


reactor.listenTCP(9000, ServerFactory(),interface='0.0.0.0')
reactor.run()
