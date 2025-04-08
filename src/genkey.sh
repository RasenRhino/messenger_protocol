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

# Generate Ed25519 key pair for signing
echo "✍️ Generating Ed25519 signing keys (Curve25519)..."
openssl genpkey -algorithm ED25519 -out "$PRIVATE_KEY_SIGNING"
openssl pkey -in "$PRIVATE_KEY_SIGNING" -pubout -out "$PUBLIC_KEY_SIGNING"

# Organize key files
rm -rf ./server/encryption_keys ./server/signing_keys
mkdir -p ./server/encryption_keys ./server/signing_keys
mv "$PRIVATE_KEY_ENCRYPTION" "$PUBLIC_KEY_ENCRYPTION" ./server/encryption_keys/
mv "$PRIVATE_KEY_SIGNING" "$PUBLIC_KEY_SIGNING" ./server/signing_keys/

echo "✅ RSA + Ed25519 key pair generation completed successfully!"
