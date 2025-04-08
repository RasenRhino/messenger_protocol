from enum import Enum
class PacketType(str, Enum):
    CS_AUTH = "cs_auth"
    ERROR = "error"
    LOGOUT = "logout"
    MESSAGE = "message"
    LIST = "list"
    # Add more packet types as needed

class ProtocolState(str, Enum):
    PRE_AUTH = "pre_auth"
    POST_AUTH = "post_auth"
    # Add more states if needed
