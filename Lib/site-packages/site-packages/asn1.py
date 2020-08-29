# -*- coding: utf-8 -*-
#
# This file is part of Python-ASN1. Python-ASN1 is free software that is
# made available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-ASN1 is copyright (c) 2007-2016 by the Python-ASN1 authors. See the
# file "AUTHORS" for a complete overview.

"""
This module provides ASN.1 encoder and decoder.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections
import re
from builtins import bytes
from builtins import int
from builtins import range
from builtins import str
from enum import IntEnum
from numbers import Number

__version__ = "2.4.1"


class Numbers(IntEnum):
    Boolean = 0x01
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    Enumerated = 0x0a
    UTF8String = 0x0c
    Sequence = 0x10
    Set = 0x11
    PrintableString = 0x13
    IA5String = 0x16
    UTCTime = 0x17
    UnicodeString = 0x1e


class Types(IntEnum):
    Constructed = 0x20
    Primitive = 0x00


class Classes(IntEnum):
    Universal = 0x00
    Application = 0x40
    Context = 0x80
    Private = 0xc0


Tag = collections.namedtuple('Tag', 'nr typ cls')
"""A named tuple to represent ASN.1 tags as returned by `Decoder.peek()` and
`Decoder.read()`."""


class Error(Exception):
    """ASN.11 encoding or decoding error."""


class Encoder(object):
    """ASN.1 encoder. Uses DER encoding.
    """

    def __init__(self):  # type: () -> None
        """Constructor."""
        self.m_stack = None

    def start(self):  # type: () -> None
        """This method instructs the encoder to start encoding a new ASN.1
        output. This method may be called at any time to reset the encoder,
        and resets the current output (if any).
        """
        self.m_stack = [[]]

    def enter(self, nr, cls=None):  # type: (int, int) -> None
        """This method starts the construction of a constructed type.

        Args:
            nr (int): The desired ASN.1 type. Use ``Numbers`` enumeration.

            cls (int): This optional parameter specifies the class
                of the constructed type. The default class to use is the
                universal class. Use ``Classes`` enumeration.

        Returns:
            None

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('Encoder not initialized. Call start() first.')
        if cls is None:
            cls = Classes.Universal
        self._emit_tag(nr, Types.Constructed, cls)
        self.m_stack.append([])

    def leave(self):  # type: () -> None
        """This method completes the construction of a constructed type and
        writes the encoded representation to the output buffer.
        """
        if self.m_stack is None:
            raise Error('Encoder not initialized. Call start() first.')
        if len(self.m_stack) == 1:
            raise Error('Tag stack is empty.')
        value = b''.join(self.m_stack[-1])
        del self.m_stack[-1]
        self._emit_length(len(value))
        self._emit(value)

    def write(self, value, nr=None, typ=None, cls=None):  # type: (object, int, int, int) -> None
        """This method encodes one ASN.1 tag and writes it to the output buffer.

        Note:
            Normally, ``value`` will be the only parameter to this method.
            In this case Python-ASN1 will autodetect the correct ASN.1 type from
            the type of ``value``, and will output the encoded value based on this
            type.

        Args:
            value (any): The value of the ASN.1 tag to write. Python-ASN1 will
                try to autodetect the correct ASN.1 type from the type of
                ``value``.

            nr (int): If the desired ASN.1 type cannot be autodetected or is
                autodetected wrongly, the ``nr`` parameter can be provided to
                specify the ASN.1 type to be used. Use ``Numbers`` enumeration.

            typ (int): This optional parameter can be used to write constructed
                types to the output by setting it to indicate the constructed
                encoding type. In this case, ``value`` must already be valid ASN.1
                encoded data as plain Python bytes. This is not normally how
                constructed types should be encoded though, see `Encoder.enter()`
                and `Encoder.leave()` for the recommended way of doing this.
                Use ``Types`` enumeration.

            cls (int): This parameter can be used to override the class of the
                ``value``. The default class is the universal class.
                Use ``Classes`` enumeration.

        Returns:
            None

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('Encoder not initialized. Call start() first.')

        if typ is None:
            typ = Types.Primitive
        if cls is None:
            cls = Classes.Universal

        if cls != Classes.Universal and nr is None:
            raise Error('Please specify a tag number (nr) when using classes Application, Context or Private')

        if nr is None:
            if isinstance(value, bool):
                nr = Numbers.Boolean
            elif isinstance(value, int):
                nr = Numbers.Integer
            elif isinstance(value, str):
                nr = Numbers.PrintableString
            elif isinstance(value, bytes):
                nr = Numbers.OctetString
            elif value is None:
                nr = Numbers.Null

        value = self._encode_value(cls, nr, value)
        self._emit_tag(nr, typ, cls)
        self._emit_length(len(value))
        self._emit(value)

    def output(self):  # type: () -> bytes
        """This method returns the encoded ASN.1 data as plain Python ``bytes``.
        This method can be called multiple times, also during encoding.
        In the latter case the data that has been encoded so far is
        returned.

        Note:
            It is an error to call this method if the encoder is still
            constructing a constructed type, i.e. if `Encoder.enter()` has been
            called more times that `Encoder.leave()`.

        Returns:
            bytes: The DER encoded ASN.1 data.

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('Encoder not initialized. Call start() first.')
        if len(self.m_stack) != 1:
            raise Error('Stack is not empty.')
        output = b''.join(self.m_stack[0])
        return output

    def _emit_tag(self, nr, typ, cls):  # type: (int, int, int) -> None
        """Emit a tag."""
        if nr < 31:
            self._emit_tag_short(nr, typ, cls)
        else:
            self._emit_tag_long(nr, typ, cls)

    def _emit_tag_short(self, nr, typ, cls):  # type: (int, int, int) -> None
        """Emit a short (< 31 bytes) tag."""
        assert nr < 31
        self._emit(bytes([nr | typ | cls]))

    def _emit_tag_long(self, nr, typ, cls):  # type: (int, int, int) -> None
        """Emit a long (>= 31 bytes) tag."""
        head = bytes([typ | cls | 0x1f])
        self._emit(head)
        values = [(nr & 0x7f)]
        nr >>= 7
        while nr:
            values.append((nr & 0x7f) | 0x80)
            nr >>= 7
        values.reverse()
        for val in values:
            self._emit(bytes([val]))

    def _emit_length(self, length):  # type: (int) -> None
        """Emit length octects."""
        if length < 128:
            self._emit_length_short(length)
        else:
            self._emit_length_long(length)

    def _emit_length_short(self, length):  # type: (int) -> None
        """Emit the short length form (< 128 octets)."""
        assert length < 128
        self._emit(bytes([length]))

    def _emit_length_long(self, length):  # type: (int) -> None
        """Emit the long length form (>= 128 octets)."""
        values = []
        while length:
            values.append(length & 0xff)
            length >>= 8
        values.reverse()
        # really for correctness as this should not happen anytime soon
        assert len(values) < 127
        head = bytes([0x80 | len(values)])
        self._emit(head)
        for val in values:
            self._emit(bytes([val]))

    def _emit(self, s):  # type: (bytes) -> None
        """Emit raw bytes."""
        assert isinstance(s, bytes)
        self.m_stack[-1].append(s)

    def _encode_value(self, cls, nr, value):  # type: (int, int, any) -> bytes
        """Encode a value."""
        if cls != Classes.Universal:
            return value
        if nr in (Numbers.Integer, Numbers.Enumerated):
            return self._encode_integer(value)
        if nr in (Numbers.OctetString, Numbers.PrintableString):
            return self._encode_octet_string(value)
        if nr == Numbers.BitString:
            return self._encode_bit_string(value)
        if nr == Numbers.Boolean:
            return self._encode_boolean(value)
        if nr == Numbers.Null:
            return self._encode_null()
        if nr == Numbers.ObjectIdentifier:
            return self._encode_object_identifier(value)
        return value

    @staticmethod
    def _encode_boolean(value):  # type: (bool) -> bytes
        """Encode a boolean."""
        return value and bytes(b'\xff') or bytes(b'\x00')

    @staticmethod
    def _encode_integer(value):  # type: (int) -> bytes
        """Encode an integer."""
        if value < 0:
            value = -value
            negative = True
            limit = 0x80
        else:
            negative = False
            limit = 0x7f
        values = []
        while value > limit:
            values.append(value & 0xff)
            value >>= 8
        values.append(value & 0xff)
        if negative:
            # create two's complement
            for i in range(len(values)):  # Invert bits
                values[i] = 0xff - values[i]
            for i in range(len(values)):  # Add 1
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i != len(values) - 1
                values[i] = 0x00
        if negative and values[len(values) - 1] == 0x7f:  # Two's complement corner case
            values.append(0xff)
        values.reverse()
        return bytes(values)

    @staticmethod
    def _encode_octet_string(value):  # type: (object) -> bytes
        """Encode an octetstring."""
        # Use the primitive encoding
        assert isinstance(value, str) or isinstance(value, bytes)
        if isinstance(value, str):
            return value.encode('utf-8')
        else:
            return value

    @staticmethod
    def _encode_bit_string(value):  # type: (object) -> bytes
        """Encode a bitstring. Assumes no unused bytes."""
        # Use the primitive encoding
        assert isinstance(value, bytes)
        return b'\x00' + value

    @staticmethod
    def _encode_null():  # type: () -> bytes
        """Encode a Null value."""
        return bytes(b'')

    _re_oid = re.compile(r'^[0-9]+(\.[0-9]+)+$')

    def _encode_object_identifier(self, oid):  # type: (str) -> bytes
        """Encode an object identifier."""
        if not self._re_oid.match(oid):
            raise Error('Illegal object identifier')
        cmps = list(map(int, oid.split('.')))
        if cmps[0] > 39 or cmps[1] > 39:
            raise Error('Illegal object identifier')
        cmps = [40 * cmps[0] + cmps[1]] + cmps[2:]
        cmps.reverse()
        result = []
        for cmp_data in cmps:
            result.append(cmp_data & 0x7f)
            while cmp_data > 0x7f:
                cmp_data >>= 7
                result.append(0x80 | (cmp_data & 0x7f))
        result.reverse()
        return bytes(result)


class Decoder(object):
    """ASN.1 decoder. Understands BER (and DER which is a subset)."""

    def __init__(self):  # type: () -> None
        """Constructor."""
        self.m_stack = None
        self.m_tag = None

    def start(self, data):  # type: (bytes) -> None
        """This method instructs the decoder to start decoding the ASN.1 input
        ``data``, which must be a passed in as plain Python bytes.
        This method may be called at any time to start a new decoding job.
        If this method is called while currently decoding another input, that
        decoding context is discarded.

        Note:
            It is not necessary to specify the encoding because the decoder
            assumes the input is in BER or DER format.

        Args:
            data (bytes): ASN.1 input, in BER or DER format, to be decoded.

        Returns:
            None

        Raises:
            `Error`
        """
        if not isinstance(data, bytes):
            raise Error('Expecting bytes instance.')
        self.m_stack = [[0, bytes(data)]]
        self.m_tag = None

    def peek(self):  # type: () -> Tag
        """This method returns the current ASN.1 tag (i.e. the tag that a
        subsequent `Decoder.read()` call would return) without updating the
        decoding offset. In case no more data is available from the input,
        this method returns ``None`` to signal end-of-file.

        This method is useful if you don't know whether the next tag will be a
        primitive or a constructed tag. Depending on the return value of `peek`,
        you would decide to either issue a `Decoder.read()` in case of a primitive
        type, or an `Decoder.enter()` in case of a constructed type.

        Note:
            Because this method does not advance the current offset in the input,
            calling it multiple times in a row will return the same value for all
            calls.

        Returns:
            `Tag`: The current ASN.1 tag.

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('No input selected. Call start() first.')
        if self._end_of_input():
            return None
        if self.m_tag is None:
            self.m_tag = self._read_tag()
        return self.m_tag

    def read(self, tagnr=None):  # type: (Number) -> (Tag, any)
        """This method decodes one ASN.1 tag from the input and returns it as a
        ``(tag, value)`` tuple. ``tag`` is a 3-tuple ``(nr, typ, cls)``,
        while ``value`` is a Python object representing the ASN.1 value.
        The offset in the input is increased so that the next `Decoder.read()`
        call will return the next tag. In case no more data is available from
        the input, this method returns ``None`` to signal end-of-file.

        Returns:
            `Tag`, value: The current ASN.1 tag and its value.

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('No input selected. Call start() first.')
        if self._end_of_input():
            return None
        tag = self.peek()
        length = self._read_length()
        if tagnr is None:
            tagnr = tag.nr
        value = self._read_value(tag.cls, tagnr, length)
        self.m_tag = None
        return tag, value

    def eof(self):  # type: () -> bool
        """Return True if we are at the end of input.

        Returns:
            bool: True if all input has been decoded, and False otherwise.
        """
        return self._end_of_input()

    def enter(self):  # type: () -> None
        """This method enters the constructed type that is at the current
        decoding offset.

        Note:
            It is an error to call `Decoder.enter()` if the to be decoded ASN.1 tag
            is not of a constructed type.

        Returns:
            None
        """
        if self.m_stack is None:
            raise Error('No input selected. Call start() first.')
        tag = self.peek()
        if tag.typ != Types.Constructed:
            raise Error('Cannot enter a non-constructed tag.')
        length = self._read_length()
        bytes_data = self._read_bytes(length)
        self.m_stack.append([0, bytes_data])
        self.m_tag = None

    def leave(self):  # type: () -> None
        """This method leaves the last constructed type that was
        `Decoder.enter()`-ed.

        Note:
            It is an error to call `Decoder.leave()` if the current ASN.1 tag
            is not of a constructed type.

        Returns:
            None
        """
        if self.m_stack is None:
            raise Error('No input selected. Call start() first.')
        if len(self.m_stack) == 1:
            raise Error('Tag stack is empty.')
        del self.m_stack[-1]
        self.m_tag = None

    def _read_tag(self):  # type: () -> Tag
        """Read a tag from the input."""
        byte = self._read_byte()
        cls = byte & 0xc0
        typ = byte & 0x20
        nr = byte & 0x1f
        if nr == 0x1f:  # Long form of tag encoding
            nr = 0
            while True:
                byte = self._read_byte()
                nr = (nr << 7) | (byte & 0x7f)
                if not byte & 0x80:
                    break
        return Tag(nr=nr, typ=typ, cls=cls)

    def _read_length(self):  # type: () -> int
        """Read a length from the input."""
        byte = self._read_byte()
        if byte & 0x80:
            count = byte & 0x7f
            if count == 0x7f:
                raise Error('ASN1 syntax error')
            bytes_data = self._read_bytes(count)
            length = 0
            for byte in bytes_data:
                length = (length << 8) | int(byte)
            try:
                length = int(length)
            except OverflowError:
                pass
        else:
            length = byte
        return length

    def _read_value(self, cls, nr, length):  # type: (int, int, int) -> any
        """Read a value from the input."""
        bytes_data = self._read_bytes(length)
        if cls != Classes.Universal:
            value = bytes_data
        elif nr == Numbers.Boolean:
            value = self._decode_boolean(bytes_data)
        elif nr in (Numbers.Integer, Numbers.Enumerated):
            value = self._decode_integer(bytes_data)
        elif nr == Numbers.OctetString:
            value = self._decode_octet_string(bytes_data)
        elif nr == Numbers.Null:
            value = self._decode_null(bytes_data)
        elif nr == Numbers.ObjectIdentifier:
            value = self._decode_object_identifier(bytes_data)
        elif nr in (Numbers.PrintableString, Numbers.IA5String, Numbers.UTCTime):
            value = self._decode_printable_string(bytes_data)
        else:
            value = bytes_data
        return value

    def _read_byte(self):  # type: () -> int
        """Return the next input byte, or raise an error on end-of-input."""
        index, input_data = self.m_stack[-1]
        try:
            byte = input_data[index]
        except IndexError:
            raise Error('Premature end of input.')
        self.m_stack[-1][0] += 1
        return byte

    def _read_bytes(self, count):  # type: (int) -> bytes
        """Return the next ``count`` bytes of input. Raise error on
        end-of-input."""
        index, input_data = self.m_stack[-1]
        bytes_data = input_data[index:index + count]
        if len(bytes_data) != count:
            raise Error('Premature end of input.')
        self.m_stack[-1][0] += count
        return bytes_data

    def _end_of_input(self):  # type: () -> bool
        """Return True if we are at the end of input."""
        index, input_data = self.m_stack[-1]
        assert not index > len(input_data)
        return index == len(input_data)

    @staticmethod
    def _decode_boolean(bytes_data):  # type: (bytes) -> bool
        """Decode a boolean value."""
        if len(bytes_data) != 1:
            raise Error('ASN1 syntax error')
        if bytes_data[0] == 0:
            return False
        return True

    @staticmethod
    def _decode_integer(bytes_data):  # type: (bytes) -> int
        """Decode an integer value."""
        values = [int(b) for b in bytes_data]
        # check if the integer is normalized
        if len(values) > 1 and (values[0] == 0xff and values[1] & 0x80 or values[0] == 0x00 and not (values[1] & 0x80)):
            raise Error('ASN1 syntax error')
        negative = values[0] & 0x80
        if negative:
            # make positive by taking two's complement
            for i in range(len(values)):
                values[i] = 0xff - values[i]
            for i in range(len(values) - 1, -1, -1):
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i > 0
                values[i] = 0x00
        value = 0
        for val in values:
            value = (value << 8) | val
        if negative:
            value = -value
        try:
            value = int(value)
        except OverflowError:
            pass
        return value

    @staticmethod
    def _decode_octet_string(bytes_data):  # type: (bytes) -> bytes
        """Decode an octet string."""
        return bytes_data

    @staticmethod
    def _decode_null(bytes_data):  # type: (bytes) -> any
        """Decode a Null value."""
        if len(bytes_data) != 0:
            raise Error('ASN1 syntax error')
        return None

    @staticmethod
    def _decode_object_identifier(bytes_data):  # type: (bytes) -> str
        """Decode an object identifier."""
        result = []
        value = 0
        for i in range(len(bytes_data)):
            byte = int(bytes_data[i])
            if value == 0 and byte == 0x80:
                raise Error('ASN1 syntax error')
            value = (value << 7) | (byte & 0x7f)
            if not byte & 0x80:
                result.append(value)
                value = 0
        if len(result) == 0 or result[0] > 1599:
            raise Error('ASN1 syntax error')
        result = [result[0] // 40, result[0] % 40] + result[1:]
        result = list(map(str, result))
        return str('.'.join(result))

    @staticmethod
    def _decode_printable_string(bytes_data):  # type: (bytes) -> str
        """Decode a printable string."""
        return bytes_data.decode('utf-8')
