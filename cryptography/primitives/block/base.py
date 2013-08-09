# TODO: which binding is used should be an option somewhere
from cryptography.bindings.openssl import api


class BlockCipher(object):
    def __init__(self, cipher, mode):
        super(BlockCipher, self).__init__()
        self.cipher = cipher
        self.mode = mode
        self._ctx = api.create_block_cipher_context(cipher, mode)


    def encrypt(self, plaintext):
        return api.update_encrypt_context(self._ctx, plaintext)

    def finalize(self):
        # TODO: this might be a decrypt context
        result = api.finalize_encrypt_context(self._ctx)
        self._ctx = None
        return result
