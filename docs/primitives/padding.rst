Padding
=======

Padding is a way to take data that may or may not be be a multiple of the block
size for a cipher and extend it out so that it is. This is required for many
block cipher modes as they require the data to be encrypted to be an exact
multiple of the block size.


.. class:: cryptography.primitives.padding.PKCS7(block_size)

    PKCS7 padding works by appending ``N`` bytes with the value of ``chr(N)``,
    where ``N`` is the number of bytes required to make the final block of data
    the same size as the cipher's block size. A Simple example of padding is:

    .. doctest::

        >>> from cryptography.primitives import padding
        >>> padder = padding.PKCS7(128)
        >>> padder.pad(b"1111111111")
        '1111111111\x06\x06\x06\x06\x06\x06'

    :param block_size: The size of the block in bits that the data is being
                       padded to.

    .. method:: pad(data)

        :param data: The data that should be padded, can be any iterable of
                     bytes or integral byte values.
        :rtype bytes: The padded data.

    .. method:: iter_pad(data):

        :param data: The data that should be padded, can be any iterable of
                     bytes or integral byte values.
        :rtype generator: A generator that yields blocks of padded data.

    .. method:: unpad(data)

        :param data: The data that should be unpadded, can be any iterable of
                     bytes or integral byte values.
        :rtype bytes: The unpadded data.

    .. method:: iter_unpad(data):

        :param data: The data that should be unpadded, can be any iterable of
                     bytes or integral byte values.
        :rtype generator: A generator that yields blocks of unpadded data.
