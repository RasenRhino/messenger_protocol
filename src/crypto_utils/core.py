# src/crypto_utils.py
from cryptography.hazmat.primitives import hashes, serialization,default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def load_private_key(file_path: str):
    """
    Load a private RSA key from a file. 

    :param file_path: Path to the private key file.
    :return: An RSA private key object.
    """
    with open(file_path, "rb") as f:
        key_data = f.read()
        return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())


def load_public_key(file_path: str):
    """
    Load a public RSA key from a file.
    :param file_path: Path to the public key file.
    :return: An RSA public key object.
    """
    with open(file_path, "rb") as f:
        key_data = f.read()
        return serialization.load_pem_public_key(key_data, backend=default_backend())



def asymmetric_decryption(private_key, ciphertext: bytes) -> bytes:
    """
    Decrypt an RSA OAEP ciphertext using the given private key.

    :param private_key: RSA private key object.
    :param ciphertext: The ciphertext bytes to decrypt.
    :return: The decrypted plaintext message as bytes.
    :raises ValueError: If the decryption fails (e.g., wrong key, corrupted data).
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def symmetric_decryption(payload, key):
    return payload  # Replace with real logic

def symmetric_encryption(payload, key):
    return payload  # Replace with real logic

def asymmetric_encryption(public_key, message: bytes) -> bytes:
    """
    Encrypt a message using RSA OAEP with SHA-256.

    :param public_key: RSA public key object.
    :param message: The plaintext message to encrypt.
    :return: The RSA-encrypted ciphertext as bytes.
    """
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def generate_dh_contribution():
    pass  # TODO

def generate_symmetric_key():
    pass  # TODO
