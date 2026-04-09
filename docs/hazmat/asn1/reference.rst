.. hazmat::

ASN.1 Reference
===============

.. currentmodule:: cryptography.hazmat.asn1

This module provides a declarative interface for defining ASN.1 structures
and serializing/deserializing them to/from DER-encoded data.

.. note::
    While usable, these APIs should be considered unstable and not yet
    subject to our backwards compatibility policy.

.. versionadded:: 47.0.0

Serialization
-------------

.. function:: decode_der(cls, data)

    Deserialize a DER-encoded byte string into an instance of ``cls``.

    :param cls: The type object representing the ASN.1 class to decode.
    :type cls: :class:`type`
    :param bytes data: The DER-encoded data.
    :returns: An instance of ``cls``.
    :raises ValueError: If the DER data could not be decoded
        successfully as an object of type ``cls``.

    .. doctest::

        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class Point:
        ...     x: int
        ...     y: int
        >>> point = asn1.decode_der(Point, b'0\x06\x02\x01\x01\x02\x01\x02')
        >>> point.x
        1
        >>> point.y
        2

.. function:: encode_der(value)

    Serialize an ASN.1 object into DER-encoded bytes.

    :param value: The ASN.1 object to encode. Must be an instance of a
        class decorated with :func:`sequence`, or a primitive ASN.1 type
        (``int``, ``bool``, ``bytes``, ``str``,
        :class:`~cryptography.x509.ObjectIdentifier`,
        :class:`PrintableString`, :class:`IA5String`, :class:`UTCTime`,
        :class:`GeneralizedTime`, :class:`BitString`, :class:`Null`).
    :returns bytes: The DER-encoded data.
    :raises ValueError: If the value could not be encoded.

    .. doctest::

        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class Point:
        ...     x: int
        ...     y: int
        >>> asn1.encode_der(Point(x=1, y=2))
        b'0\x06\x02\x01\x01\x02\x01\x02'

ASN.1 types
-----------

The following built-in Python types are supported as ASN.1 field types:

* ``int`` -- ``INTEGER``
* ``bool`` -- ``BOOLEAN``
* ``bytes`` -- ``OCTET STRING``
* ``str`` -- ``UTF8String``

Additionally, :class:`~cryptography.x509.ObjectIdentifier` maps to
``OBJECT IDENTIFIER``.

The following decorators and types are provided for the rest of the ASN.1 types
that have no direct Python equivalent:

.. decorator:: sequence

    A class decorator that registers a class as an ASN.1 ``SEQUENCE``. Fields
    are defined as class-level type annotations. The decorator adds an
    ``__init__`` method with keyword-only parameters.

    Fields can be annotated with :class:`Explicit`, :class:`Implicit`,
    :class:`Default`, and :class:`Size` using :class:`typing.Annotated`.

    .. doctest::

        >>> import typing
        >>> from typing import Annotated
        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class AlgorithmIdentifier:
        ...     algorithm: int
        ...     parameters: typing.Union[bool, bytes, None]
        >>> encoded = asn1.encode_der(AlgorithmIdentifier(algorithm=9, parameters=None))
        >>> asn1.decode_der(AlgorithmIdentifier, encoded).algorithm
        9

.. class:: PrintableString(value)

    Wraps ASN.1 ``PrintableString`` values. ``PrintableString`` is a restricted
    subset of ASCII containing only letters, digits, and a limited set
    of punctuation characters.

    :param str value: The string value. Must contain only characters valid
        for ASN.1 ``PrintableString``.
    :raises ValueError: If the string contains invalid characters.

    .. method:: as_str()

        :returns str: The underlying string value.

.. class:: IA5String(value)

    Wraps ASN.1 ``IA5String`` values. ``IA5String`` is equivalent to ASCII.

    :param str value: The string value. Must contain only valid ASCII
        characters (0--127).
    :raises ValueError: If the string contains invalid characters.

    .. method:: as_str()

        :returns str: The underlying string value.

.. class:: UTCTime(value)

    Wraps ASN.1 ``UTCTime`` values. ``UTCTime`` represents dates between 1950 and
    2049 with second precision.

    :param value: An aware datetime object (must have ``tzinfo`` set).
        Year must be between 1950 and 2049. Fractional seconds are not
        supported.
    :type value: :class:`datetime.datetime`
    :raises ValueError: If the datetime is naive, out of range, or has
        fractional seconds.

    .. method:: as_datetime()

        :returns: :class:`datetime.datetime` -- The underlying datetime value.

.. class:: GeneralizedTime(value)

    Wraps ASN.1 ``GeneralizedTime`` values. ``GeneralizedTime`` can represent any
    date and supports microsecond precision.

    :param value: An aware datetime object (must have ``tzinfo`` set).
    :type value: :class:`datetime.datetime`
    :raises ValueError: If the datetime is naive.

    .. method:: as_datetime()

        :returns: :class:`datetime.datetime` -- The underlying datetime value.

.. class:: BitString(data, padding_bits)

    Wraps ASN.1 ``BIT STRING`` values.

    :param bytes data: The raw bit string data.
    :param int padding_bits: The number of unused bits in the last byte
        (0--7). The unused bits in the last byte of ``data`` must all be
        zero.
    :raises ValueError: If ``padding_bits`` is greater than 7, or if the
        unused bits in the last byte are not zero.

    .. method:: as_bytes()

        :returns bytes: The raw bit string data.

    .. method:: padding_bits()

        :returns int: The number of unused bits in the last byte.

.. class:: Null()

    Represents the ASN.1 ``NULL`` type. ``NULL`` has no value and is encoded as a
    zero-length element.

.. class:: TLV

    Represents a raw ASN.1 Tag-Length-Value element. This is useful for
    decoding ASN.1 ``ANY`` fields, deferring the decoding of parts of a
    structure, or for handling fields whose type is not known at
    definition time.

    ``TLV`` cannot be directly constructed. It is obtained by decoding
    DER data. It cannot have :class:`Implicit` or :class:`Default`
    annotations, and cannot be optional (``TLV | None``).

    .. attribute:: tag_bytes

        The raw tag bytes of the element.

        :type: :class:`bytes`

    .. attribute:: data

        The raw content bytes (value) of the element, excluding the tag
        and length.

        :type: :class:`memoryview`

    .. method:: parse(cls)

        Parse the TLV data as an instance of ``cls``.

        :param cls: The type to decode the TLV contents as.
        :type cls: :class:`type`
        :returns: An instance of ``cls``.

    .. doctest::

        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class Inner:
        ...     foo: int
        >>> # Decode a SEQUENCE's raw bytes as a TLV
        >>> raw = asn1.decode_der(asn1.TLV, asn1.encode_der(Inner(foo=9)))
        >>> raw.tag_bytes
        b'0'
        >>> inner = raw.parse(Inner)
        >>> inner.foo
        9

.. class:: SetOf(values)

    Represents an ASN.1 ``SET OF``, an unordered collection of elements of a
    single type.

    :param list values: The list of values.

    .. method:: as_list()

        :returns list: The underlying list of values.

    .. doctest::

        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class Example:
        ...     values: asn1.SetOf[int]
        >>> encoded = asn1.encode_der(Example(values=asn1.SetOf([3, 1, 2])))
        >>> decoded = asn1.decode_der(Example, encoded)
        >>> decoded.values.as_list()
        [1, 2, 3]

.. class:: Variant(value, tag)

    A tagged variant for ``CHOICE`` fields where multiple alternatives share
    the same underlying type.

    When a ``CHOICE`` field has multiple alternatives with different types,
    use a :class:`~typing.Union` directly. When multiple alternatives share the same
    underlying type, use ``Variant`` to distinguish between them with a
    string tag.

    :param value: The actual value.
    :param str tag: A string tag identifying which variant this is. Must
        match a ``typing.Literal`` type parameter in the type annotation.

    .. attribute:: value

        The wrapped value.

    .. attribute:: tag

        The string tag identifying which variant this is.

    .. doctest::

        >>> import typing
        >>> from typing import Annotated
        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class Example:
        ...     field: typing.Union[
        ...         Annotated[asn1.Variant[int, typing.Literal["IntA"]], asn1.Implicit(0)],
        ...         Annotated[asn1.Variant[int, typing.Literal["IntB"]], asn1.Implicit(1)],
        ...     ]
        >>> obj = Example(field=asn1.Variant(9, "IntA"))
        >>> encoded = asn1.encode_der(obj)
        >>> decoded = asn1.decode_der(Example, encoded)
        >>> decoded.field.value
        9
        >>> decoded.field.tag
        'IntA'

A field with a ``Union[X, None]`` (or ``X | None``) type annotation is
treated as ASN.1 ``OPTIONAL``. When the value is ``None``, the field is
omitted from the encoding.

.. doctest::

    >>> import typing
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Example:
    ...     required: int
    ...     optional: typing.Union[str, None]
    >>> with_value = asn1.encode_der(Example(required=1, optional="hi"))
    >>> without_value = asn1.encode_der(Example(required=1, optional=None))
    >>> asn1.decode_der(Example, without_value).optional is None
    True

A field with a ``Union`` of multiple non-``None`` types is treated as an
ASN.1 ``CHOICE``. Each variant in the union must have a distinct ASN.1 tag.

.. doctest::

    >>> import typing
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Example:
    ...     value: typing.Union[int, bool, str]
    >>> asn1.decode_der(Example, asn1.encode_der(Example(value=42))).value
    42

Annotations
-----------

Annotations are applied to fields using :class:`typing.Annotated` to
control ASN.1 encoding behavior.

.. class:: Explicit(tag)

    An annotation that applies ``EXPLICIT`` tagging to a field. ``EXPLICIT`` tagging
    wraps the original encoding in a new tag.

    :param int tag: The context-specific tag number.

    .. doctest::

        >>> from typing import Annotated
        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class Example:
        ...     value: Annotated[int, asn1.Explicit(0)]
        >>> asn1.encode_der(Example(value=9))
        b'0\x05\xa0\x03\x02\x01\t'

.. class:: Implicit(tag)

    An annotation that applies ``IMPLICIT`` tagging to a field. ``IMPLICIT`` tagging
    replaces the original tag with a context-specific tag.

    Cannot be used with ``CHOICE`` types or :class:`TLV` fields.

    :param int tag: The context-specific tag number.

    .. doctest::

        >>> from typing import Annotated
        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class Example:
        ...     value: Annotated[int, asn1.Implicit(0)]
        >>> asn1.encode_der(Example(value=9))
        b'0\x03\x80\x01\t'

.. class:: Default(value)

    An annotation that specifies a ``DEFAULT`` value for a field. When encoding,
    if the field's value equals the default, it is omitted from the output.
    When decoding, if the field is absent, the default value is used.

    Cannot be used with ``OPTIONAL`` (``X | None``) fields or :class:`TLV`
    fields.

    :param value: The default value for the field.

    .. doctest::

        >>> from typing import Annotated
        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class Example:
        ...     version: Annotated[int, asn1.Default(0)]
        ...     data: bytes
        >>> encoded = asn1.encode_der(Example(version=0, data=b"\x01"))
        >>> encoded
        b'0\x03\x04\x01\x01'
        >>> asn1.decode_der(Example, encoded).version
        0

.. class:: Size(min, max)

    An annotation that applies a size constraint to a field. Supported on
    ``SEQUENCE OF``, ``SET OF``, ``BIT STRING``, ``OCTET STRING``,
    ``UTF8String``, ``PrintableString``, and ``IA5String`` fields.

    :param int min: The minimum size (inclusive).
    :param max: The maximum size (inclusive), or ``None`` for no upper
        bound.
    :type max: :class:`int` or ``None``

    .. staticmethod:: exact(n)

        Create a :class:`Size` constraint where the minimum and maximum are
        both ``n``.

        :param int n: The exact size required.
        :returns: :class:`Size`

    .. doctest::

        >>> import typing
        >>> from typing import Annotated
        >>> from cryptography.hazmat import asn1
        >>> @asn1.sequence
        ... class Example:
        ...     values: Annotated[typing.List[int], asn1.Size(min=1, max=4)]
        >>> asn1.encode_der(Example(values=[1, 2]))
        b'0\x080\x06\x02\x01\x01\x02\x01\x02'
