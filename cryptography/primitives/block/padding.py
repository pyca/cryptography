import itertools

import six


def _chunker(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)


class PKCS7(object):

    def __init__(self, block_size):
        self.block_size = block_size
        self.byte_size = block_size / 8

    def pad(self, data):
        def _pad(data):
            # Iterate over the data yielding it in chunks the size of our
            # blocks until there's only one block left equal to or less than
            # the block size.
            chunked = _chunker(data, self.byte_size)
            last_chunk = next(chunked)
            for chunk in chunked:
                chunk, last_chunk = last_chunk, chunk
                yield b"".join(chunk)

            # Determine size of padding
            padsize = last_chunk.count(None) or self.byte_size

            # Create a padding bytechunk
            byte_chunk = b"".join([c for c in last_chunk if c is not None])

            # Actually pad the byte_chunk
            if padsize:
                byte_chunk += chr(padsize) * padsize

            yield byte_chunk

        if isinstance(data, six.binary_type):
            return b"".join(_pad(data))
        else:
            return _pad(data)

    def unpad(self, data):
        def _unpad(data):
            # Iterate over the data yielding it in chunks the size of our
            # blocks until there's only one block left equal to or less than
            # the block size.
            chunked = _chunker(data, self.byte_size)
            last_chunk = b"".join(next(chunked))
            for chunk in chunked:
                chunk = b"".join(chunk)
                chunk, last_chunk = last_chunk, chunk
                yield chunk

            # Determine size of padding
            padsize = ord(last_chunk[-1])

            # Ensure that the last padsize characters match our padchar
            if set(last_chunk[-padsize:]) != set([chr(padsize)]):
                raise Exception("Bad Padding")

            # yield the last chunk of data with the padding removed
            yield last_chunk[:-padsize]

        if isinstance(data, six.binary_type):
            return b"".join(_unpad(data))
        else:
            return _unpad(data)
