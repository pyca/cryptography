import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils


class SimplifiedRSA:
    # ------------------------------------------- INIT -----------------------------------------------------------------
    def __init__(self):
        self._keychain = {}
        self.hash_algorithm = hashes.SHA256()

    # ------------------------------------- KEYCHAIN STRUCTURE ---------------------------------------------------------
    def _create_keychain(self, keychain: str):
        if keychain not in self._keychain:
            self._keychain[keychain] = {
                'private': None,
                'public': None
            }

    def _get_key(self, keychain: str, mode: str):
        return self._keychain[keychain][mode]

    def _set_key(self, keychain: str, mode: str, key):
        self._keychain[keychain][mode] = key

    # ------------------------------------ KEYCHAIN OPERATIONS ---------------------------------------------------------
    def generate(self, keychain: str):
        if keychain not in self._keychain:
            self._create_keychain(keychain)

            # generate private
            self._set_key(keychain=keychain, mode='private', key=rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            ))

            # generate public key to this private key
            self._set_key(keychain=keychain, mode='public',
                          key=self._get_key(keychain=keychain, mode='private').public_key())
        else:
            raise ValueError('keychain already exists: %s' % keychain)

    # ----------------------------------------------- FILE OPERATIONS --------------------------------------------------
    def save_public_key(self, keychain: str, filename: str):
        with open(filename, 'wb') as file:
            _public_key = self._get_key(keychain=keychain, mode='public').public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1
            )
            file.write(_public_key)

    def save_private_key(self, keychain: str, filename: str):
        with open(filename, 'wb') as file:
            _private_key = self._get_key(keychain=keychain, mode='private').private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            file.write(_private_key)

    def load_public_key(self, keychain: str, filename: str):
        self._create_keychain(keychain)
        with open(filename, "rb") as file:
            self._set_key(keychain=keychain, mode='public',
                          key=serialization.load_pem_public_key(
                              data=file.read(),
                              backend=default_backend())
                          )

    def load_private_key(self, keychain: str, filename: str):
        with open(filename, 'rb') as file:
            key = file.read()
            self._set_key(keychain=keychain, mode='private',
                          key=serialization.load_pem_private_key(key, None, default_backend()))

    # ---------------------------- MESSAGE OPERATIONS ------------------------------------------------------------------
    def encrypt(self, keychain: str, message: str) -> str:
        message_bytes = bytes(message, encoding='utf8') if not isinstance(message, bytes) else message
        cipher = self._get_key(keychain=keychain, mode='public').encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_algorithm),
                algorithm=self.hash_algorithm,
                label=None
            )
        )
        return str(base64.urlsafe_b64encode(cipher), encoding='utf-8')

    def decrypt(self, keychain: str, message: str) -> str:
        cipher_decoded = base64.urlsafe_b64decode(message) if not isinstance(message, bytes) else message
        plain_text = self._get_key(keychain=keychain, mode='private').decrypt(
            cipher_decoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_algorithm),
                algorithm=self.hash_algorithm,
                label=None
            )
        )
        return str(plain_text, encoding='utf8')

    def sign(self, keychain: str, message: str) -> (str, str):
        hash_method = self.hash_algorithm
        message = bytes(message, encoding='utf8') if not isinstance(message, bytes) else message
        hash_generator = hashes.Hash(hash_method, default_backend())
        hash_generator.update(message)
        digest = hash_generator.finalize()
        signature = self._get_key(keychain=keychain, mode='private').sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hash_method),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hash_method)
        )
        return signature

    def verify(self, keychain: str, message: str, signature) -> bool:
        try:
            plain_text_bytes = bytes(message, encoding='utf8') if not isinstance(message, bytes) else message
            signature = base64.b64decode(signature) if not isinstance(signature, bytes) else signature
            self._get_key(keychain=keychain, mode='public').verify(
                signature=signature,
                padding=padding.PSS(
                    mgf=padding.MGF1(self.hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                data=plain_text_bytes,
                algorithm=self.hash_algorithm
            )
            return True
        except InvalidSignature:
            return False


if __name__ == '__main__':
    # init test
    simple_RSA = SimplifiedRSA()
    simple_RSA.generate(keychain='alice')
    simple_RSA.generate(keychain='bob')

    _message = 'simple text'

    # crypting test
    encrypted_message = simple_RSA.encrypt(keychain='alice', message=_message)
    decrypted_message = simple_RSA.decrypt(keychain='alice', message=encrypted_message)
    print(decrypted_message)

    # file manipulation test
    simple_RSA.save_public_key(keychain='alice', filename='public_alice.pem')
    simple_RSA.save_private_key(keychain='alice', filename='private_alice.pem')
    simple_RSA.load_public_key(keychain='alice', filename='public_alice.pem')
    simple_RSA.load_private_key(keychain='alice', filename='private_alice.pem')

    # signing test
    _signature = simple_RSA.sign(keychain='alice', message=_message)
    print(simple_RSA.verify(keychain='alice', message=_message, signature=_signature))
    print(simple_RSA.verify(keychain='alice', message="lorem ipsum", signature=_signature))
