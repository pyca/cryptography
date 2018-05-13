.. hazmat::

Symmetric Padding
=================

.. module:: cryptography.hazmat.primitives.padding

Padding is a way to take data that may or may not be a multiple of the block
size for a cipher and extend it out so that it is. This is required for many
block cipher modes as they require the data to be encrypted to be an exact
multiple of the block size.


.. class:: PKCS7(block_size)

    PKCS7 padding is a generalization of PKCS5 padding (also known as standard
    padding). PKCS7 padding works by appending ``N`` bytes with the value of
    ``chr(N)``, where ``N`` is the number of bytes required to make the final
    block of data the same size as the block size. A simple example of padding
    is:

    .. doctest::

        >>> from cryptography.hazmat.primitives import padding
        >>> padder = padding.PKCS7(128).padder()
        >>> padded_data = padder.update(b"11111111111111112222222222")
        >>> padded_data
        b'1111111111111111'
        >>> padded_data += padder.finalize()
        >>> padded_data
        b'11111111111111112222222222\x06\x06\x06\x06\x06\x06'
        >>> unpadder = padding.PKCS7(128).unpadder()
        >>> data = unpadder.update(padded_data)
        >>> data
        b'1111111111111111'
        >>> data + unpadder.finalize()
        b'11111111111111112222222222'

    :param block_size: The size of the block in :term:`bits` that the data is
        being padded to.
    :raises ValueError: Raised if block size is not a multiple of 8 or is not
        between 0 and 2040 inclusive.

    .. method:: padder()

        :returns: A padding
            :class:`~cryptography.hazmat.primitives.padding.PaddingContext`
            instance.

    .. method:: unpadder()

        :returns: An unpadding
            :class:`~cryptography.hazmat.primitives.padding.PaddingContext`
            instance.


.. class:: ANSIX923(block_size)

    .. versionadded:: 1.3

    `ANSI X.923`_ padding works by appending ``N-1`` bytes with the value of
    ``0`` and a last byte with the value of ``chr(N)``, where ``N`` is the
    number of bytes required to make the final block of data the same size as
    the block size. A simple example of padding is:

    .. doctest::

        >>> padder = padding.ANSIX923(128).padder()
        >>> padded_data = padder.update(b"11111111111111112222222222")
        >>> padded_data
        b'1111111111111111'
        >>> padded_data += padder.finalize()
        >>> padded_data
        b'11111111111111112222222222\x00\x00\x00\x00\x00\x06'
        >>> unpadder = padding.ANSIX923(128).unpadder()
        >>> data = unpadder.update(padded_data)
        >>> data
        b'1111111111111111'
        >>> data + unpadder.finalize()
        b'11111111111111112222222222'

    :param block_size: The size of the block in :term:`bits` that the data is
        being padded to.
    :raises ValueError: Raised if block size is not a multiple of 8 or is not
        between 0 and 2040 inclusive.

    .. method:: padder()

        :returns: A padding
            :class:`~cryptography.hazmat.primitives.padding.PaddingContext`
            instance.

    .. method:: unpadder()

        :returns: An unpadding
            :class:`~cryptography.hazmat.primitives.padding.PaddingContext`
            instance.


.. class:: PaddingContext

    When calling ``padder()`` or ``unpadder()`` the result will conform to the
    ``PaddingContext`` interface. You can then call ``update(data)`` with data
    until you have fed everything into the context. Once that is done call
    ``finalize()`` to finish the operation and obtain the remainder of the
    data.

    .. method:: update(data)

        :param bytes data: The data you wish to pass into the context.
        :return bytes: Returns the data that was padded or unpadded.
        :raises TypeError: Raised if data is not bytes.
        :raises cryptography.exceptions.AlreadyFinalized: See :meth:`finalize`.
        :raises TypeError: This exception is raised if ``data`` is not ``bytes``.

    .. method:: finalize()

        Finalize the current context and return the rest of the data.

        After ``finalize`` has been called this object can no longer be used;
        :meth:`update` and :meth:`finalize` will raise an
        :class:`~cryptography.exceptions.AlreadyFinalized` exception.

        :return bytes: Returns the remainder of the data.
        :raises TypeError: Raised if data is not bytes.
        :raises ValueError: When trying to remove padding from incorrectly
                            padded data.

.. _`ANSI X.923`: https://en.wikipedia.org/wiki/Padding_%28cryptography%29#ANSI_X.923
