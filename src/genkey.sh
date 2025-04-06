#!/bin/bash

# Create folders for key organization
mkdir -p encryption_keys 
mkdir -p signing_keys 

# Define output filenames
PRIVATE_KEY_ENCRYPTION="private_key_encryption.pem"
PUBLIC_KEY_ENCRYPTION="public_key_encryption.pem"
PRIVATE_KEY_SIGNING="private_key_signing.pem"
PUBLIC_KEY_SIGNING="public_key_signing.pem"

# Generate the private keys
echo "Generating private RSA keys in PEM format..."
openssl genrsa -out "$PRIVATE_KEY_ENCRYPTION" 2048
openssl genrsa -out "$PRIVATE_KEY_SIGNING" 2048

# Generate the public keys from private keys
echo "Generating corresponding public RSA keys in PEM format..."
openssl rsa -in "$PRIVATE_KEY_ENCRYPTION" -pubout -out "$PUBLIC_KEY_ENCRYPTION"
openssl rsa -in "$PRIVATE_KEY_SIGNING" -pubout -out "$PUBLIC_KEY_SIGNING"

# Move encryption-related keys to encryption_keys/
mv "$PRIVATE_KEY_ENCRYPTION" "$PUBLIC_KEY_ENCRYPTION" encryption_keys/

# Move signing-related keys to signing_keys/
mv "$PRIVATE_KEY_SIGNING" "$PUBLIC_KEY_SIGNING" signing_keys/

echo "✅ RSA key pair generation completed successfully!"
