class BlockCipher(object):
    def __init__(self, cipher, mode):
        super(BlockCipher, self).__init__()
        self.cipher = cipher
        self.mode = mode

    def encrypt(self, plaintext):
        raise NotImplementedError
