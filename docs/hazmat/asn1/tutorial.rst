.. hazmat::

Tutorial
========

.. note::
    While usable, these APIs should be considered unstable and not yet
    subject to our backwards compatibility policy.

The :mod:`cryptography.hazmat.asn1` module provides a declarative API for
working with ASN.1 data. ASN.1 structures are defined as Python classes
with type annotations, and the module uses those definitions to
serialize and deserialize instances to and from DER-encoded bytes.

Type mapping
------------

The following table shows how ASN.1 types map to Python types:

.. list-table::
   :header-rows: 1

   * - ASN.1 type
     - Python type
   * - ``BOOLEAN``
     - :class:`bool`
   * - ``INTEGER``
     - :class:`int`
   * - ``BIT STRING``
     - :class:`~cryptography.hazmat.asn1.BitString`
   * - ``OCTET STRING``
     - :class:`bytes`
   * - ``NULL``
     - :class:`~cryptography.hazmat.asn1.Null`
   * - ``OBJECT IDENTIFIER``
     - :class:`~cryptography.x509.ObjectIdentifier`
   * - ``UTF8String``
     - :class:`str`
   * - ``PrintableString``
     - :class:`~cryptography.hazmat.asn1.PrintableString`
   * - ``IA5String``
     - :class:`~cryptography.hazmat.asn1.IA5String`
   * - ``UTCTime``
     - :class:`~cryptography.hazmat.asn1.UTCTime`
   * - ``GeneralizedTime``
     - :class:`~cryptography.hazmat.asn1.GeneralizedTime`
   * - ``SEQUENCE``
     - :func:`@sequence <cryptography.hazmat.asn1.sequence>`-decorated class
   * - ``SEQUENCE OF``
     - :class:`list`\[T]
   * - ``SET OF``
     - :class:`~cryptography.hazmat.asn1.SetOf`\[T]
   * - ``CHOICE``
     - ``X | Y | ...``
   * - ``ANY``
     - :class:`~cryptography.hazmat.asn1.TLV`
   * - ``OPTIONAL``
     - ``X | None``

Defining a SEQUENCE
-------------------

ASN.1 ``SEQUENCE`` types map to Python classes decorated with
:func:`@sequence <cryptography.hazmat.asn1.sequence>`. Fields are defined as type annotations. For example,
given the following ASN.1 definition:

.. code-block:: none

    Point ::= SEQUENCE {
         x      INTEGER,
         y      INTEGER }

The corresponding Python definition is:

.. doctest::

    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Point:
    ...     x: int
    ...     y: int

The decorator adds an ``__init__`` with keyword-only parameters:

.. doctest::

    >>> p = Point(x=3, y=7)
    >>> p.x
    3

Encoding and decoding
---------------------

Use :func:`~cryptography.hazmat.asn1.encode_der` to serialize an ASN.1 object to DER bytes, and
:func:`~cryptography.hazmat.asn1.decode_der` to deserialize:

.. doctest::

    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Point:
    ...     x: int
    ...     y: int
    >>> encoded = asn1.encode_der(Point(x=1, y=2))
    >>> encoded
    b'0\x06\x02\x01\x01\x02\x01\x02'
    >>> point = asn1.decode_der(Point, encoded)
    >>> point.x
    1
    >>> point.y
    2

Primitive types can also be encoded and decoded directly, without wrapping
them in a sequence:

.. doctest::

    >>> asn1.encode_der(42)
    b'\x02\x01*'
    >>> asn1.decode_der(int, b'\x02\x01*')
    42

Nested sequences
----------------

Sequences can contain other sequences as field types:

.. doctest::

    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Name:
    ...     value: str
    >>> @asn1.sequence
    ... class Certificate:
    ...     version: int
    ...     subject: Name
    >>> cert = Certificate(version=1, subject=Name(value="Alice"))
    >>> decoded = asn1.decode_der(Certificate, asn1.encode_der(cert))
    >>> decoded.subject.value
    'Alice'

OPTIONAL fields
---------------

A field with a ``Union[X, None]`` (or ``X | None``) type annotation is
treated as ASN.1 ``OPTIONAL``. When the value is ``None``, the field is
omitted from the encoding:

.. doctest::

    >>> import typing
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Record:
    ...     required: int
    ...     optional: typing.Union[str, None]
    >>> asn1.encode_der(Record(required=1, optional="hi"))
    b'0\x07\x02\x01\x01\x0c\x02hi'
    >>> asn1.encode_der(Record(required=1, optional=None))
    b'0\x03\x02\x01\x01'

DEFAULT values
--------------

Use :class:`~cryptography.hazmat.asn1.Default` with :data:`typing.Annotated` to specify a default
value for a field. When encoding, if the field's value equals the default,
it is omitted. When decoding, if the field is absent, the default is used:

.. doctest::

    >>> from typing import Annotated
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class VersionedRecord:
    ...     version: Annotated[int, asn1.Default(0)]
    ...     data: bytes
    >>> asn1.encode_der(VersionedRecord(version=1, data=b"\x01"))
    b'0\x06\x02\x01\x01\x04\x01\x01'
    >>> # version=0 equals the default, so it is omitted from the encoding
    >>> asn1.encode_der(VersionedRecord(version=0, data=b"\x01"))
    b'0\x03\x04\x01\x01'

CHOICE fields
-------------

A field with a ``Union`` of multiple non-``None`` types is treated as an
ASN.1 ``CHOICE``. Each variant must have a distinct ASN.1 tag:

.. doctest::

    >>> import typing
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Example:
    ...     value: typing.Union[int, bool, str]
    >>> asn1.decode_der(Example, asn1.encode_der(Example(value=42))).value
    42
    >>> asn1.decode_der(Example, asn1.encode_der(Example(value=True))).value
    True

When multiple alternatives share the same underlying type, a plain union
can't distinguish them (``Union[int, int]`` is just ``int``). Wrap the types with
:class:`~cryptography.hazmat.asn1.Variant` and add
:class:`~cryptography.hazmat.asn1.Implicit` tags to differentiate
between them:

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
    >>> decoded = asn1.decode_der(Example, asn1.encode_der(obj))
    >>> decoded.field.value
    9
    >>> decoded.field.tag
    'IntA'

EXPLICIT and IMPLICIT tagging
------------------------------

Use :class:`~cryptography.hazmat.asn1.Explicit` and :class:`~cryptography.hazmat.asn1.Implicit` annotations to apply ASN.1
context-specific tags to fields:

.. doctest::

    >>> from typing import Annotated
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Tagged:
    ...     explicit_field: Annotated[int, asn1.Explicit(0)]
    ...     implicit_field: Annotated[int, asn1.Implicit(1)]
    >>> encoded = asn1.encode_der(Tagged(explicit_field=5, implicit_field=10))
    >>> decoded = asn1.decode_der(Tagged, encoded)
    >>> decoded.explicit_field
    5
    >>> decoded.implicit_field
    10

Tagging is typically needed to disambiguate ``OPTIONAL`` fields that would
otherwise share the same tag:

.. doctest::

    >>> import typing
    >>> from typing import Annotated
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Example:
    ...     a: Annotated[typing.Union[int, None], asn1.Implicit(0)]
    ...     b: Annotated[typing.Union[int, None], asn1.Implicit(1)]
    >>> asn1.decode_der(Example, asn1.encode_der(Example(a=9, b=None))).a
    9
    >>> asn1.decode_der(Example, asn1.encode_der(Example(a=None, b=9))).b
    9

SEQUENCE OF and SET OF
----------------------

Use :class:`list`\[T] for ``SEQUENCE OF`` and :class:`~cryptography.hazmat.asn1.SetOf` for
``SET OF``:

.. doctest::

    >>> import typing
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class IntList:
    ...     values: typing.List[int]
    >>> decoded = asn1.decode_der(IntList, asn1.encode_der(IntList(values=[1, 2, 3])))
    >>> decoded.values
    [1, 2, 3]

``SET OF`` elements are sorted in DER encoding:

.. doctest::

    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class IntSet:
    ...     values: asn1.SetOf[int]
    >>> decoded = asn1.decode_der(IntSet, asn1.encode_der(IntSet(values=asn1.SetOf([3, 1, 2]))))
    >>> decoded.values.as_list()
    [1, 2, 3]

Size constraints
----------------

Use :class:`~cryptography.hazmat.asn1.Size` to restrict the length of collection and string fields:

.. doctest::

    >>> import typing
    >>> from typing import Annotated
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class BoundedList:
    ...     values: Annotated[typing.List[int], asn1.Size(min=1, max=4)]
    >>> asn1.encode_der(BoundedList(values=[1, 2]))
    b'0\x080\x06\x02\x01\x01\x02\x01\x02'

A real-world example
--------------------

Here is a more complete example modeling the X.509 ``Validity`` structure:

.. code-block:: none

    Validity ::= SEQUENCE {
         notBefore      Time,
         notAfter       Time  }

    Time ::= CHOICE {
         utcTime        UTCTime,
         generalTime    GeneralizedTime }

This translates to:

.. doctest::

    >>> import typing
    >>> import datetime
    >>> from typing import Annotated
    >>> from cryptography.hazmat import asn1
    >>> @asn1.sequence
    ... class Validity:
    ...     not_before: typing.Union[asn1.UTCTime, asn1.GeneralizedTime]
    ...     not_after: typing.Union[asn1.UTCTime, asn1.GeneralizedTime]
    >>> not_before = asn1.UTCTime(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
    >>> not_after = asn1.UTCTime(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
    >>> validity = Validity(not_before=not_before, not_after=not_after)
    >>> decoded = asn1.decode_der(Validity, asn1.encode_der(validity))
    >>> decoded.not_before.as_datetime().year
    2025
    >>> decoded.not_after.as_datetime().year
    2026
