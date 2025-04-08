class InvalidErrorPacket(Exception):
    pass

class ServerPreAuthError(Exception):
    pass

class InvalidSeqNumber(Exception):
    pass

class InvalidNonce(Exception):
    pass

class ChallengeResponseFailed(Exception):
    pass