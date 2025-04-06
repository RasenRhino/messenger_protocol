from dataclasses import dataclass
from typing import Optional

@dataclass
class Metadata:
    packet_type: str
    state: Optional[str] = None  # "pre-auth", "post_auth", etc.
    salt: Optional[str] = None
    dh_contribution: Optional[int] = None
    iv: Optional[str] = None
    tag: Optional[str] = None

@dataclass
class Payload:
    seq: Optional[int] = None
    username: Optional[str] = None
    nonce: Optional[str] = None
    server_challenge: Optional[str] = None
    server_challenge_solution: Optional[str] = None
    client_challenge: Optional[str] = None
    client_challenge_solution: Optional[str] = None
    encryption_public_key: Optional[str] = None
    signature_verification_public_key: Optional[str] = None
    listening_ip: Optional[str] = None
    message: Optional[str] = None
    signature: Optional[str] = None

@dataclass
class Message:
    metadata: Metadata
    payload: Payload
