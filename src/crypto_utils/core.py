# src/crypto_utils/core.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
def load_private_key(file_path: str):
    """
    Load a private RSA key from a file. 

    :param file_path: Path to the private key file.
    :return: An RSA private key object.
    """
    with open(file_path, "rb") as f:
        key_data = f.read()
        return serialization.load_pem_private_key(key_data, password=None )


def load_public_key(file_path: str):
    """
    Load a public RSA key from a file.
    :param file_path: Path to the public key file.
    :return: An RSA public key object.
    """
    with open(file_path, "rb") as f:
        key_data = f.read()
        return serialization.load_pem_public_key(key_data)



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



def symmetric_decryption(key: bytes, payload:bytes ,iv:bytes, tag: bytes, aad: bytes) -> bytes:
    """
    Decrypt AES-GCM encrypted data.
    :param key: The symmetric AES key.
    :param payload: The ciphertext.
    :param iv: Initialization vector (nonce) used during encryption.
    :param tag: Authentication tag generated during encryption.
    :param aad: Additional authenticated data used in encryption.
    :return: Decrypted plaintext bytes.
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(aad)
    # Perform decryption
    plaintext = decryptor.update(payload) + decryptor.finalize()
    return plaintext
def symmetric_encryption(key: bytes, payload: str, aad: str) -> dict:
    """
    Encrypts a plaintext payload using AES-GCM with the provided key and additional authenticated data (AAD).

    Args:
        key (bytes): A symmetric key for AES encryption. Should be 16, 24, or 32 bytes long.
        payload (str): The plaintext message to encrypt.
        aad (str): Additional Authenticated Data (AAD) to bind to the ciphertext. This data will not be encrypted,
                   but any tampering will be detected upon decryption.
                   'packet_type' is used as AAD.

    Returns:
        dict: A dictionary containing:
            - 'cipher_text': The encrypted payload (base64-encoded).
            - 'iv': The initialization vector used in encryption (base64-encoded).
            - 'tag': The GCM authentication tag (base64-encoded).
            - 'AAD': The original AAD, also base64-encoded for transmission/storage.
    """
    associated_data = aad.encode('utf-8')
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(associated_data)

    payload = payload.encode('utf-8')
    cipher_text = encryptor.update(payload) + encryptor.finalize()
    tag = encryptor.tag

    return {
        "cipher_text": base64.b64encode(cipher_text).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "AAD": base64.b64encode(associated_data).decode('utf-8')
    }

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

def generate_symmetric_key(g,p,hashed_key):
    #Ritik
    key="12345678"*4
    key=key.encode('utf-8')
    return key
    
