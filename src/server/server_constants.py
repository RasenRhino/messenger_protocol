from enum import Enum
class PacketType(str, Enum):
    CS_AUTH = "cs_auth"
    ERROR = "error"
    LOGOUT = "logout"
    MESSAGE = "message"
    LIST = "list"
    # Add more packet types as needed

class ProtocolState(str, Enum):
    PRE_AUTH = "pre-auth"
    POST_AUTH = "post-auth"
    # Add more states if needed
