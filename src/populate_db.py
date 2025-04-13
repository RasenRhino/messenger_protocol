import os
import json
import sqlite3
import random
import string
import sys
import argparse
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Replace these imports with wherever you keep them:
from config.config import load_dh_public_params
from crypto_utils.core import H, argon2_hash

ROOT_DIR = str(Path(__file__).parent.resolve())
JSON_FILE = f"{ROOT_DIR}/userdetails.json"
DB_FILE = f"{ROOT_DIR}/store.db"
TABLE_NAME = "users"

def generate_salt(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_key():
    # For testing, we generate short numeric passwords
    return ''.join(random.choices(string.digits, k=1))

def hash_password_with_salt(password, salt):
    return H(salt, password)

def generate_verifier(salt, username, password):
    x = argon2_hash(salt, username, password)
    g, N, _ = load_dh_public_params()
    v = pow(g, x, N)
    return v

def create_user_details(user_data_dict):
    """
    user_data_dict should be in form:
    {
      "Alice": {"password": "..."},
      "Bob":   {"password": "..."},
      ...
    }
    We generate salt and verifier for each user, then store in a dict:
    {
      "Alice": {"password": "x", "salt": "y", "verifier": "0xZ..."},
      ...
    }
    """
    user_details = {}
    for username, data in user_data_dict.items():
        # If user didn't provide a password, generate a placeholder.
        # This is just a fallback; typically you'd handle errors or validations.
        password = data.get("password") or generate_key()
        salt = generate_salt()
        verifier = generate_verifier(salt, username, password)
        user_details[username] = {
            "password": password,
            "salt": salt,
            "verifier": hex(verifier)
        }
    # Dump to JSON_FILE
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
    # Drop table if it exists, then create new
    cursor.execute(f"DROP TABLE IF EXISTS {TABLE_NAME}")
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
    """
    If --file is provided, load that file instead of creating dummy data.
    Otherwise, create data for ["Alice", "Bob", "Mallory"].
    """
    parser = argparse.ArgumentParser(description="Initialize user details and store them in an SQLite database.")
    parser.add_argument("--file", "-f", help="Path to a JSON file containing user data (username -> password).")
    args = parser.parse_args()

    if args.file:
        # Read user data from the provided JSON file
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"Error: file '{args.file}' does not exist.")
            sys.exit(1)
        with open(file_path, 'r') as f:
            user_data_dict = json.load(f)
    else:
        # Dummy data mode
        user_data_dict = {
            "Alice":   {"password": generate_key()},
            "Bob":     {"password": generate_key()},
            "Mallory": {"password": generate_key()},
        }

    # Create userdetails.json with salts and verifiers
    user_details = create_user_details(user_data_dict)

    # (Optional) Print to console for verification
    print(json.dumps(user_details, indent=4))

    # Initialize the database
    init_db(user_details)

if __name__ == "__main__":
    main()
