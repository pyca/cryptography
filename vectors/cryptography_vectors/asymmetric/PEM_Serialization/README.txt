Example test files for PEM Serialization Backend tests

Contains

1. ec_private_key.pem - Contains an Elliptic Curve key generated using OpenSSL, from the curve secp256k1.
2. ec_private_key_encrypted.pem - Contains the same Elliptic Curve key as ec_private_key.pem, except that 
   it is encrypted with AES-256 with the password "123456".