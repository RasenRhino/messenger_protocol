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

class DecryptionFailed(Exception):
    pass
class ServerError(Exception):
    pass

class LogoutClient(Exception):
    pass

class IdentityVerificationFailed(Exception):
    pass

class StopClient(Exception):
    pass