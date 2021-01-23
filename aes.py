from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, sys
iv_key=os.urandom(16)
backend=default_backend()
mypassword=b"thisismylongestpasswordicoulhave"
messagetodigest=b"Happy New Year!!"
message_additional=b"Not secret"
aescipher=Cipher(algorithms.AES(mypassword), modes.CTR(iv_key), backend=backend)
encryptor=aescipher.encryptor()
encrypt_text=encryptor.update(messagetodigest)+encryptor.finalize()
aescipher=Cipher(algorithms.AES(mypassword), modes.CTR(iv_key), backend=backend)
decryptor=aescipher.decryptor()
decrypt_text=decryptor.update(encrypt_text)+decryptor.finalize()
assert decrypt_text,messagetodigest
print(messagetodigest.decode())
