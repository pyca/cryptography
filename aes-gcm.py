from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
backend=default_backend()
nonce=os.urandom(12)
message_to_encrypt=b"Hello World, Happy New Year!!"
additional_message=b"Not Secret"
key=AESGCM.generate_key(bit_length=256)
aes_gcm=AESGCM(key)
encrypt_message=aes_gcm.encrypt(nonce, message_to_encrypt, additional_message)
assert message_to_encrypt,aes_gcm.decrypt(nonce, encrypt_message, additional_message)
print(aes_gcm.decrypt(nonce, encrypt_message, additional_message).decode())