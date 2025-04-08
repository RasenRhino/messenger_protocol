import os
import json
import sqlite3
import random
import string
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sys
from pathlib import Path

ROOT_DIR = str(Path(__file__).parent.parent.resolve())+'/src'
print(ROOT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)
from config.config import load_dh_public_params
from crypto_utils.core import H
JSON_FILE = "userdetails.json"
DB_FILE = "store.db"
TABLE_NAME = "users"

# def H(*args):
#     a = ":".join(str(a) for a in args)
#     return int(hashlib.sha3_512(a.encode()).hexdigest(), 16)
def generate_salt(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_key():
    return ''.join(random.choices(string.digits, k=1)) # k=1 is for testing

def hash_password_with_salt(password, salt):
    return H(salt,password)
    # digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    # digest.update((password + salt).encode())
    # print(f"Hashing: {(password + salt).encode()}")
    # return digest.finalize().hex()
def generate_verifier(salt,username,password):
    x = H(salt,username,password)
    g,N,_=load_dh_public_params()
    v = pow(g, x, N)
    return v
def create_user_details(usernames):
    user_details = {}
    for username in usernames:
        key = generate_key()
        salt = generate_salt()
        verifier = generate_verifier(salt,username,key) 
        user_details[username] = {
            "password": key,
            "salt": salt,
            "verifier":hex(verifier)
        }
    with open(JSON_FILE, 'w') as f:
        json.dump(user_details, f, indent=4)
    print(f"Created {JSON_FILE} with user details.")
    return user_details

def load_user_details():
    with open(JSON_FILE, 'r') as f:
        return json.load(f)

def init_db(user_details):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Drop table if it exists
    cursor.execute(f"DROP TABLE IF EXISTS {TABLE_NAME}")

    # Create new table
    cursor.execute(f'''
        CREATE TABLE {TABLE_NAME} (
            username TEXT PRIMARY KEY,
            verifier TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')

    # Insert user data
    for username, details in user_details.items():
        cursor.execute(f'''
            INSERT INTO {TABLE_NAME} (username, verifier, salt)
            VALUES (?, ?, ?)
        ''', (username, details["verifier"], details["salt"]))
        
    conn.commit()
    conn.close()
    print(f"Table '{TABLE_NAME}' overwritten and user data inserted into {DB_FILE}.")

def main():
    usernames = ["Alice", "Bob", "Mallory"]
    create_user_details(usernames)
    user_details = load_user_details() 
    print(json.dumps(user_details, indent=4))
    init_db(user_details)

if __name__ == "__main__":
    main()
