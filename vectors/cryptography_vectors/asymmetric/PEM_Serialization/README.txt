Example test files for PEM Serialization Backend tests

Contains

1. ec_private_key.pem - Contains an Elliptic Curve key generated using OpenSSL, from the curve secp256r1.
2. ec_private_key_encrypted.pem - Contains the same Elliptic Curve key as ec_private_key.pem, except that
   it is encrypted with AES-256 with the password "123456".
3. ec_public_key.pem - Contains the public key corresponding to ec_private_key.pem, generated using OpenSSL.
4. rsa_private_key.pem - Contains an RSA 2048 bit key generated using OpenSSL, protected by the secret
   "123456" with DES3 encryption.
5. rsa_public_key.pem - Contains an RSA 2048 bit public generated using OpenSSL from rsa_private_key.pem.
6. dsaparam.pem - Contains 2048-bit DSA parameters generated using OpenSSL; contains no keys.
7. dsa_private_key.pem - Contains a DSA 2048 bit key generated using OpenSSL from the parameters in
   dsaparam.pem, protected by the secret "123456" with DES3 encryption.
8. dsa_public_key.pem - Contains a DSA 2048 bit key generated using OpenSSL from dsa_private_key.pem.
