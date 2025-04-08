import hashlib
import hmac
import os

# Constants (for real use, N should be at least 2048 bits)
N = int('EEAF0AB9ADB38DD69C33F80AFA8FC5E860726187' \
        '75FF3C0B9EA2314C9C256576D674DF7496EA81D3' \
        '385B3C1C63BF1B9F048393C70BA1DF1527D2B9C2' \
        'A274FA15836D21B2A0D1B1E2C9E3BF', 16)
g = 2

def H(*args):
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha3_512(a.encode()).hexdigest(), 16)

def random_bigint(n_bytes=32):
    return int.from_bytes(os.urandom(n_bytes), 'big')

def generate_challenge():
    return os.urandom(16).hex()

def hash_challenge(ch):
    return hashlib.sha3_256(ch.encode()).hexdigest()

# Step 0: Registration (one-time)
def register(username, password, salt=None):
    salt = salt or os.urandom(16).hex()
    x = H(salt, username, password)
    v = pow(g, x, N)
    return {"username": username, "salt": salt, "verifier": v}

# Server-side persistent DB entry
server_db = register("Alice", "SuperSecure123!")

# Step 1: Client → Server
a = random_bigint()
A = pow(g, a, N)
nonce_client = os.urandom(16).hex()

msg1 = {
    "metadata": {"packet_type": "cs_auth"},
    "payload": {
        "seq": 1,
        "username": "Alice",
        "dh_contribution": A,
        "nonce": nonce_client
    }
}

# Step 2: Server → Client
b = random_bigint()
B = (H(N, g) * server_db['verifier'] + pow(g, b, N)) % N
nonce_server = os.urandom(16).hex()
u = H(A, B)
server_challenge = generate_challenge()

msg2 = {
    "metadata": {
        "packet_type": "cs_auth",
        "salt": server_db['salt'],
        "dh_contribution": B,
        "iv": "iv",  # Placeholder
        "tag": "tag"
    },
    "payload": {
        "seq": 2,
        "server_challenge": server_challenge,
        "nonce": nonce_client
    }
}

# Step 3: Client computes session key
x = H(server_db['salt'], "Alice", "SuperSecure123!")
S_c = pow(B - H(N, g) * pow(g, x, N), a + u * x, N)
K_c = H(S_c)

server_challenge_solution = hash_challenge(server_challenge)
client_challenge = generate_challenge()

msg3 = {
    "metadata": {
        "packet_type": "cs_auth",
        "iv": "iv",
        "tag": "tag"
    },
    "payload": {
        "seq": 3,
        "server_challenge_solution": server_challenge_solution,
        "client_challenge": client_challenge
    }
}

# Step 4: Server validates challenge and responds
S_s = pow(A * pow(server_db['verifier'], u, N), b, N)
K_s = H(S_s)

assert H(S_c) == H(S_s), "Key mismatch!"

client_challenge_solution = hash_challenge(client_challenge)

msg4 = {
    "metadata": {
        "packet_type": "cs_auth",
        "iv": "iv",
        "tag": "tag"
    },
    "payload": {
        "seq": 4,
        "client_challenge_solution": client_challenge_solution
    }
}

# Step 5: Final Identity Exchange (Encrypted w/ K_s)
msg5 = {
    "metadata": {
        "packet_type": "cs_auth",
        "iv": "iv",
        "tag": "tag"
    },
    "payload": {
        "seq": 5,
        "username": "Alice",
        "encryption_public_key": "epk",
        "signature_verification_public_key": "spk",
        "listening_ip": "192.168.1.2"
    }
}
