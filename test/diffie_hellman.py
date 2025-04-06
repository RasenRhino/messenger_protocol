import random

# Publicly agreed prime and base
p = 23  # Prime number
g = 5   # Primitive root mod 23

# Alice generates a private key
a = random.randint(1, p-2)
A = pow(g, a, p)  # A = g^a mod p

# Bob generates a private key
b = random.randint(1, p-2)
B = pow(g, b, p)  # B = g^b mod p

# Exchange public keys (A and B)

# Alice computes shared secret
shared_secret_alice = pow(B, a, p)

# Bob computes shared secret
shared_secret_bob = pow(A, b, p)

# They should match
print("Alice's Shared Secret:", shared_secret_alice)
print("Bob's Shared Secret:  ", shared_secret_bob)
