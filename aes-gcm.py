from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
backend = default_backend()
pwd=b"i7uJ7ZDx3O5BAHZWiCV4c4XrES0Jotgm"
msg=b"Hello World, My name is Fernando!!!! The password is 256 bit long."
aed=b"saltallovermypassword"
iv=os.urandom(27)
cipher=Cipher(algorithms.AES(pwd), modes.GCM(iv), backend=backend)
e=cipher.encryptor()
e.authenticate_additional_data(aed)
ct=e.update(msg) + e.finalize()
tag=e.tag
cipher=Cipher(algorithms.AES(pwd), modes.GCM(iv,tag), backend=backend)
d=cipher.decryptor()
d.authenticate_additional_data(aed)
clear=d.update(ct)+d.finalize()
assert clear,msg
x = clear.decode()
print(x)
