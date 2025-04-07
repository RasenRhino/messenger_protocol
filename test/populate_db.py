import os
import json
import sqlite3
import random
import string

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

JSON_FILE = "userdetails.json"
DB_FILE = "store.db"
TABLE_NAME = "users"

def generate_salt(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_key():
    return ''.join(random.choices(string.digits, k=6))

def hash_password_with_salt(password, salt):
    digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest.update((password + salt).encode())
    print(f"Hashing: {(password + salt).encode()}")
    return digest.finalize().hex()

def create_user_details(usernames):
    user_details = {}
    for username in usernames:
        key = generate_key()
        salt = generate_salt()
        hashed_key = hash_password_with_salt(key, salt)
        user_details[username] = {
            "key": key,
            "salt": salt,
            "hashed": hashed_key
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
            hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')

    # Insert user data
    for username, details in user_details.items():
        cursor.execute(f'''
            INSERT INTO {TABLE_NAME} (username, hash, salt)
            VALUES (?, ?, ?)
        ''', (username, details["hashed"], details["salt"]))
        
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
