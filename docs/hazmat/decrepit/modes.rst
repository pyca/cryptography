.. hazmat::


Decrepit Cipher Modes
=====================

.. module:: cryptography.hazmat.decrepit.ciphers.modes

This module contains decrepit cipher modes. These modes should not be used
unless necessary for backwards compatibility or interoperability with legacy
systems. Their use is **strongly discouraged**.

These modes work with :class:`~cryptography.hazmat.primitives.ciphers.Cipher`
objects in the same way as modes from
:mod:`~cryptography.hazmat.primitives.ciphers.modes`.

.. class:: CFB(initialization_vector)

    .. versionadded:: 47.0.0

    CFB (Cipher Feedback) is a mode of operation for block ciphers. It
    transforms a block cipher into a stream cipher.

    **This mode does not require padding.**

    :param initialization_vector: Must be random and unpredictable. It must
        be the same length as the cipher's block size.
    :type initialization_vector: :term:`bytes-like`

.. class:: CFB8(initialization_vector)

    .. versionadded:: 47.0.0

    CFB8 (Cipher Feedback with 8-bit segment size) is a mode of operation
    similar to CFB. It operates on 8-bit segments rather than full blocks.

    **This mode does not require padding.**

    :param initialization_vector: Must be random and unpredictable. It must
        be the same length as the cipher's block size.
    :type initialization_vector: :term:`bytes-like`

.. class:: OFB(initialization_vector)

    .. versionadded:: 47.0.0

    OFB (Output Feedback) is a mode of operation for block ciphers. It
    transforms a block cipher into a stream cipher.

    **This mode does not require padding.**

    :param initialization_vector: Must be random and unpredictable. It must
        be the same length as the cipher's block size.
    :type initialization_vector: :term:`bytes-like`
