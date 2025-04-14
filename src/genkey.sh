#!/bin/bash

# Create folders for key organization
mkdir -p encryption_keys 
mkdir -p signing_keys 

# Define output filenames
PRIVATE_KEY_ENCRYPTION="private_key_encryption.pem"
PUBLIC_KEY_ENCRYPTION="public_key_encryption.pem"
PRIVATE_KEY_SIGNING="private_key_signing.pem"
PUBLIC_KEY_SIGNING="public_key_signing.pem"

# Generate RSA key pair for encryption
echo "🔐 Generating RSA encryption keys..."
openssl genrsa -out "$PRIVATE_KEY_ENCRYPTION" 2048
openssl rsa -in "$PRIVATE_KEY_ENCRYPTION" -pubout -out "$PUBLIC_KEY_ENCRYPTION"

# Generate RSA key pair for signing
openssl genrsa -out "$PRIVATE_KEY_SIGNING" 2048
openssl rsa -in "$PRIVATE_KEY_SIGNING" -pubout -out "$PUBLIC_KEY_SIGNING"

# Organize key files
rm -rf ./server/encryption_keys ./server/signing_keys
rm -rf ./config/encryption_keys ./config/signing_keys
mkdir -p ./server/encryption_keys ./server/signing_keys
mkdir -p ./config/encryption_keys ./config/signing_keys
cp -r "$PRIVATE_KEY_ENCRYPTION" "$PUBLIC_KEY_ENCRYPTION" ./server/encryption_keys/
cp -r "$PRIVATE_KEY_SIGNING" "$PUBLIC_KEY_SIGNING" ./server/signing_keys/
cp -r "$PRIVATE_KEY_ENCRYPTION" "$PUBLIC_KEY_ENCRYPTION" ./config/encryption_keys/
cp -r "$PRIVATE_KEY_SIGNING" "$PUBLIC_KEY_SIGNING" ./config/signing_keys/

echo "✅ RSA key pair generation completed successfully!"
