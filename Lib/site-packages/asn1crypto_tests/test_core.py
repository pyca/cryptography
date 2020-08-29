# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
from datetime import datetime, timedelta

from asn1crypto import core, util

from .unittest_data import data_decorator, data
from ._unittest_compat import patch

patch()

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class NamedBits(core.BitString):
    _map = {
        0: 'zero',
        1: 'one',
        2: 'two',
        3: 'three',
        4: 'four',
        6: 'six',
        7: 'seven',
    }


class SequenceOfInts(core.SequenceOf):
    _child_spec = core.Integer


class SequenceAny(core.SequenceOf):
    _child_spec = core.Any


class Seq(core.Sequence):
    _fields = [
        ('id', core.ObjectIdentifier),
        ('value', core.Any),
    ]

    _oid_pair = ('id', 'value')
    _oid_specs = {
        '1.2.3': core.Integer,
        '2.3.4': core.OctetString,
    }


class CopySeq(core.Sequence):
    _fields = [
        ('name', core.UTF8String),
        ('pair', Seq),
    ]


class NestSeqAny(core.Sequence):
    _fields = [
        ('id', core.ObjectIdentifier),
        ('value', core.Any),
    ]

    _oid_pair = ('id', 'value')
    _oid_specs = {
        '2.3.4.5': Seq,
    }


class NestSeqExplicit(core.Sequence):
    _fields = [
        ('id', core.ObjectIdentifier),
        ('value', NamedBits),
    ]

    _oid_pair = ('id', 'value')
    _oid_specs = {
        '2.3.4.5': Seq,
    }


class Enum(core.Enumerated):
    _map = {
        0: 'a',
        1: 'b',
    }


class ExplicitFieldDefault(core.Sequence):
    _fields = [
        ('bits', NamedBits),
        ('seq', Seq, {'explicit': 2, 'default': {'id': '1.2.3', 'value': 10}}),
    ]


class NumChoice(core.Choice):
    _alternatives = [
        ('one', core.Integer, {'explicit': 0}),
        ('two', core.Integer, {'implicit': 1}),
        ('three', core.Integer, {'explicit': 2}),
    ]


class NumChoiceOldApi(core.Choice):
    _alternatives = [
        ('one', core.Integer, {'tag_type': 'explicit', 'tag': 0}),
        ('two', core.Integer, {'tag_type': 'implicit', 'tag': 1}),
        ('three', core.Integer, {'tag_type': 'explicit', 'tag': 2}),
    ]


class SeqChoice(core.Choice):
    _alternatives = [
        ('one', CopySeq, {'explicit': 0}),
        ('two', CopySeq, {'implicit': 1}),
    ]


class SeqChoiceOldApi(core.Choice):
    _alternatives = [
        ('one', CopySeq, {'tag_type': 'explicit', 'tag': 0}),
        ('two', CopySeq, {'tag_type': 'implicit', 'tag': 1}),
    ]


class ChoiceChoice(core.Choice):
    _alternatives = [
        ('num', NumChoice, {'explicit': 0}),
        ('seq', SeqChoice, {'explicit': 1}),
    ]


class CCSeq(core.Sequence):
    _fields = [
        ('cc', ChoiceChoice)
    ]


class ExplicitField(core.Sequence):
    _fields = [
        ('field', NumChoice, {'tag_type': 'explicit', 'tag': 0}),
    ]


class ExplicitFieldOldApi(core.Sequence):
    _fields = [
        ('field', NumChoiceOldApi, {'explicit': 0}),
    ]


class SetTest(core.Set):
    _fields = [
        ('two', core.Integer, {'tag_type': 'implicit', 'tag': 2}),
        ('one', core.Integer, {'tag_type': 'implicit', 'tag': 1}),
    ]


class SetTestOldApi(core.Set):
    _fields = [
        ('two', core.Integer, {'implicit': 2}),
        ('one', core.Integer, {'implicit': 1}),
    ]


class SetOfTest(core.SetOf):
    _child_spec = core.Integer


class ConcatTest(core.Concat):
    _child_specs = [Seq, core.Integer]


class IntegerConcats(core.Concat):
    _child_specs = [core.Integer, core.Integer]


class MyOids(core.ObjectIdentifier):
    _map = {
        '1.2.3': 'abc',
        '4.5.6': 'def',
    }


class ApplicationTaggedInteger(core.Integer):
    # This class attribute may be a 2-element tuple of integers,
    # or a tuple of 2-element tuple of integers. The first form
    # will be converted to the second form the first time an
    # object of this type is constructed.
    explicit = ((1, 10), )


class ApplicationTaggedInner(core.Sequence):
    """
    TESTCASE DEFINITIONS EXPLICIT TAGS ::=
    BEGIN

    INNERSEQ ::= SEQUENCE {
        innernumber       [21] INTEGER
    }

    INNER ::= [APPLICATION 20] INNERSEQ
    """

    explicit = (1, 20)

    _fields = [
        ('innernumber', core.Integer, {'explicit': 21}),
    ]


class ApplicationTaggedOuter(core.Sequence):
    """
    OUTERSEQ ::= SEQUENCE {
        outernumber  [11] INTEGER,
        inner        [12] INNER
    }

    OUTER ::= [APPLICATION 10] OUTERSEQ
    END
    """

    explicit = (1, 10)

    _fields = [
        ('outernumber', core.Integer, {'explicit': 11}),
        ('inner', ApplicationTaggedInner, {'explicit': 12}),
    ]


class SpcPeImageFlags(core.BitString):
    _map = {
        0: "includeResources",
        1: "includeDebugInfo",
        2: "includeImportAddressTable",
    }


class SpcSerializedObject(core.Sequence):
    _fields = [
        ("classId", core.OctetString),
        ("serializedData", core.OctetString),
    ]


class SpcString(core.Choice):
    _alternatives = [
        ("unicode", core.BMPString, {"implicit": 0}),
        ("ascii", core.IA5String, {"implicit": 1}),
    ]


class SpcLink(core.Choice):
    _alternatives = [
        ("url", core.IA5String, {"implicit": 0}),
        ("moniker", SpcSerializedObject, {"implicit": 1}),
        ("file", SpcString, {"explicit": 2})
    ]


class SpcPeImageData(core.Sequence):
    _fields = [
        ("flags", SpcPeImageFlags, {"default": "includeResources"}),
        ("file", SpcLink, {"explicit": 0})
    ]


class UTF8Sequence(core.Sequence):
    _fields = [
        ("string", core.UTF8String)
    ]


class NestedUTF8Sequence(core.Sequence):
    _fields = [
        ("seq", UTF8Sequence)
    ]


@data_decorator
class CoreTests(unittest.TestCase):

    def test_large_tag_encode(self):
        # https://misc.daniel-marschall.de/asn.1/oid_facts.html
        v = core.Primitive(tag=31, contents=b'')
        self.assertEqual(b'\x1f\x1f\x00', v.dump())

        v = core.Primitive(tag=36, contents=b'')
        self.assertEqual(b'\x1f\x24\x00', v.dump())

        # One extra byte
        v = core.Primitive(
            class_="application",
            method="constructed",
            tag=73,
            contents=b''
        )
        self.assertEqual(b'\x7f\x49\x00', v.dump())

        # Two extra bytes
        v = core.Primitive(
            class_="application",
            method="constructed",
            tag=201,
            contents=b''
        )
        self.assertEqual(b'\x7f\x81\x49\x00', v.dump())

        # Three extra bytes
        v = core.Primitive(
            class_="application",
            method="constructed",
            tag=16384,
            contents=b''
        )
        self.assertEqual(b'\x7f\x81\x80\x00\x00', v.dump())

    def test_manual_construction(self):
        v = core.Asn1Value(
            class_="application",
            method="constructed",
            tag=1,
            contents=b''
        )
        self.assertEqual(b'\x61\x00', v.dump())

    def test_sequence_spec(self):
        seq = Seq()
        seq['id'] = '1.2.3'
        self.assertEqual(core.Integer, seq.spec('value'))
        seq['id'] = '2.3.4'
        self.assertEqual(core.OctetString, seq.spec('value'))

    def test_sequence_of_spec(self):
        seq = SequenceAny()
        self.assertEqual(core.Any, seq.spec())

    @staticmethod
    def compare_primitive_info():
        return (
            (core.ObjectIdentifier('1.2.3'), core.ObjectIdentifier('1.2.3'), True),
            (core.Integer(1), Enum(1), False),
            (core.Integer(1), core.Integer(1, implicit=5), True),
            (core.Integer(1), core.Integer(1, explicit=5), True),
            (core.Integer(1), core.Integer(2), False),
            (core.OctetString(b''), core.OctetString(b''), True),
            (core.OctetString(b''), core.OctetString(b'1'), False),
            (core.OctetString(b''), core.OctetBitString(b''), False),
            (core.ParsableOctetString(b'12'), core.OctetString(b'12'), True),
            (core.ParsableOctetBitString(b'12'), core.OctetBitString(b'12'), True),
            (core.UTF8String('12'), core.UTF8String('12'), True),
            (core.UTF8String('12'), core.UTF8String('1'), False),
            (core.UTF8String('12'), core.IA5String('12'), False),
        )

    @data('compare_primitive_info')
    def compare_primitive(self, one, two, equal):
        if equal:
            self.assertEqual(one, two)
        else:
            self.assertNotEqual(one, two)

    @staticmethod
    def integer_info():
        return (
            (0, b'\x02\x01\x00'),
            (255, b'\x02\x02\x00\xFF'),
            (128, b'\x02\x02\x00\x80'),
            (127, b'\x02\x01\x7F'),
            (-127, b'\x02\x01\x81'),
            (-127, b'\x02\x01\x81'),
            (32768, b'\x02\x03\x00\x80\x00'),
            (-32768, b'\x02\x02\x80\x00'),
            (-32769, b'\x02\x03\xFF\x7F\xFF'),
        )

    @data('integer_info')
    def integer(self, native, der_bytes):
        i = core.Integer(native)
        self.assertEqual(der_bytes, i.dump())
        self.assertEqual(native, core.Integer.load(der_bytes).native)

    @staticmethod
    def utctime_info():
        return (
            (datetime(2030, 12, 31, 8, 30, 0, tzinfo=util.timezone.utc), b'\x17\x0D301231083000Z'),
            (datetime(2049, 12, 31, 8, 30, 0, tzinfo=util.timezone.utc), b'\x17\x0D491231083000Z'),
            (datetime(1950, 12, 31, 8, 30, 0, tzinfo=util.timezone.utc), b'\x17\x0D501231083000Z'),
            (datetime(2018, 10, 20, 7, 35, 4, tzinfo=util.timezone(timedelta(hours=7, minutes=40))),
             b'\x17\x0D181019235504Z'),
        )

    @data('utctime_info')
    def utctime(self, native, der_bytes):
        u = core.UTCTime(native)
        self.assertEqual(der_bytes, u.dump())
        self.assertEqual(native, core.UTCTime.load(der_bytes).native)

    def test_utctime_errors(self):
        with self.assertRaises(ValueError):
            # is not aware
            core.UTCTime(datetime.fromtimestamp(1234567890))

        with self.assertRaises(ValueError):
            # Is pre 1950
            core.UTCTime(datetime(1910, 6, 22, 11, 33, 44, tzinfo=util.timezone.utc))

        with self.assertRaises(ValueError):
            # Is past 2050
            core.UTCTime(datetime(2106, 2, 7, 6, 28, 16, tzinfo=util.timezone.utc))

    def test_utctime_copy(self):
        a = core.UTCTime(datetime(2019, 11, 11, 17, 45, 18, tzinfo=util.timezone.utc))
        # Ensure _native is set because we want to test copy on the nested timezone object.
        a.native
        b = a.copy()
        self.assertEqual(a.native, b.native)
        self.assertEqual(a.contents, b.contents)
        self.assertEqual(a.dump(), b.dump())

    @staticmethod
    def generalized_time_info():
        def tz(hours, minutes=0):
            return util.create_timezone(timedelta(hours=hours, minutes=minutes))

        return (
            (b'\x18\x1520180405062426.0+0200', datetime(2018, 4, 5, 6, 24, 26, 0, tz(2)), b'\x18\x0f20180405042426Z'),
            (b'\x18\x0f2018062419-1355', datetime(2018, 6, 24, 19, 0, 0, 0, tz(-13, -55)), b'\x18\x0f20180625085500Z'),
            (b'\x18\x0d2018062419-13', datetime(2018, 6, 24, 19, 0, 0, 0, tz(-13)), b'\x18\x0f20180625080000Z'),
            (b'\x18\x0b2018062419Z', datetime(2018, 6, 24, 19, 0, 0, 0, tz(0)), b'\x18\x0f20180624190000Z'),
            (b'\x18\x122018062419.15+0345', datetime(2018, 6, 24, 19, 9, 0, 0, tz(3, 45)), b'\x18\x0f20180624152400Z'),
            (
                b'\x18\x13201806241957,433+02',
                datetime(2018, 6, 24, 19, 57, 25, 980000, tz(2)),
                b'\x18\x1220180624175725.98Z',
            ),
            (
                b'\x18\x1620180624195724.215999Z',
                datetime(2018, 6, 24, 19, 57, 24, 215999, tz(0)),
                b'\x18\x1620180624195724.215999Z',
            ),
            (
                b'\x18\x150000022910.31337-0815',
                util.extended_datetime(0, 2, 29, 10, 18, 48, 132000, tz(-8, -15)),
                b'\x18\x1300000229183348.132Z',
            ),
            (b'\x18\x1520180624195724.215999', datetime(2018, 6, 24, 19, 57, 24, 215999), None),
            (b'\x18\x0a2018062419', datetime(2018, 6, 24, 19, 0, 0, 0), None),
        )

    @data('generalized_time_info')
    def generalized_time(self, ber_bytes, native, der_bytes):
        decoded = core.GeneralizedTime.load(ber_bytes)

        self.assertEqual(decoded.native, native)
        self.assertEqual(decoded.native.tzinfo, native.tzinfo)

        if der_bytes is not None:
            encoded = core.GeneralizedTime(native).dump()
            self.assertEqual(encoded, der_bytes)

            decoded2 = core.GeneralizedTime.load(encoded)
            self.assertEqual(decoded2.native, native)
        else:
            with self.assertRaises(ValueError):
                encoded = core.GeneralizedTime(native).dump()

    @staticmethod
    def type_info():
        return (
            ('universal/object_identifier.der', core.ObjectIdentifier, '1.2.840.113549.1.1.1'),
        )

    @data('type_info')
    def parse_universal_type(self, input_filename, type_class, native):
        with open(os.path.join(fixtures_dir, input_filename), 'rb') as f:
            der = f.read()
            parsed = type_class.load(der)

        self.assertEqual(native, parsed.native)
        self.assertEqual(der, parsed.dump(force=True))

    def test_int_to_bit_tuple(self):
        self.assertEqual((), core._int_to_bit_tuple(0, 0))
        self.assertEqual((0,), core._int_to_bit_tuple(0, 1))
        self.assertEqual((1,), core._int_to_bit_tuple(1, 1))
        self.assertEqual((0, 0), core._int_to_bit_tuple(0, 2))
        self.assertEqual((0, 1), core._int_to_bit_tuple(1, 2))
        self.assertEqual((0, 0, 1), core._int_to_bit_tuple(1, 3))
        self.assertEqual((0, 1, 0), core._int_to_bit_tuple(2, 3))
        self.assertEqual((1, 0, 1), core._int_to_bit_tuple(5, 3))

        with self.assertRaises(ValueError):
            core._int_to_bit_tuple(9, 3)
        with self.assertRaises(ValueError):
            core._int_to_bit_tuple(-9, 5)

    @staticmethod
    def bit_string_info():
        return (
            ((0, 1, 1), b'\x03\x02\x05\x60'),
            ((0, 1, 1, 0, 0, 0, 0, 0), b'\x03\x02\x00\x60'),
            ((0, 0, 0, 0, 0, 0, 0, 0), b'\x03\x02\x00\x00'),
            ((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), b'\x03\x03\x00\x00\x01'),
        )

    @data('bit_string_info')
    def bit_string(self, native, der_bytes):
        bs = core.BitString(native)
        self.assertEqual(der_bytes, bs.dump())
        self.assertEqual(native, core.BitString.load(der_bytes).native)

    def test_bit_string_load_dump(self):
        bs = core.BitString.load(b'\x03\x01\x00')
        self.assertEqual(tuple(), bs.native)
        self.assertEqual(b'\x03\x01\x00', bs.dump(True))

    @staticmethod
    def bit_string_error_values():
        return (
            # unused bits in empty bit string
            (b'\x03\x01\x05',),
            # too many unused bits
            (b'\x03\x03\x0e\x0c\x00',),
            # chunk with unused bits is not last chunk
            (b'\x23\x80\x03\x02\x01\xfe\x03\x02\x00\x55\x00\x00',),
        )

    @data('bit_string_error_values')
    def bit_string_errors(self, enc_bytes):
        with self.assertRaises(ValueError):
            core.BitString.load(enc_bytes).native

    def test_cast(self):
        a = core.OctetBitString(b'\x00\x01\x02\x03')
        self.assertEqual(b'\x00\x01\x02\x03', a.native)
        b = a.cast(core.BitString)
        self.assertIsInstance(b, core.BitString)
        self.assertEqual(
            (
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1,
                0, 0, 0, 0, 0, 0, 1, 0,
                0, 0, 0, 0, 0, 0, 1, 1
            ),
            b.native
        )
        c = a.cast(core.IntegerBitString)
        self.assertIsInstance(c, core.IntegerBitString)
        self.assertEqual(66051, c.native)

    def test_load(self):
        i = core.load(b'\x02\x01\x00')
        self.assertIsInstance(i, core.Integer)
        self.assertEqual(0, i.native)

    def test_load_wrong_type(self):
        with self.assertRaises(TypeError):
            core.load('\x02\x01\x00')

    @staticmethod
    def truncated_der_byte_strings():
        return (
            (b'',),
            (b'\x30',),
            (b'\x30\x03\x02\x00\x02',),
        )

    @data('truncated_der_byte_strings')
    def truncated(self, der_bytes):
        with self.assertRaises(ValueError):
            core.load(der_bytes).native

    def test_strict(self):
        with self.assertRaises(ValueError):
            core.load(b'\x02\x01\x00\x00', strict=True)

    def test_strict_on_class(self):
        with self.assertRaises(ValueError):
            core.Integer.load(b'\x02\x01\x00\x00', strict=True)

    def test_strict_concat(self):
        with self.assertRaises(ValueError):
            IntegerConcats.load(b'\x02\x01\x00\x02\x01\x00\x00', strict=True)

    def test_strict_choice(self):
        with self.assertRaises(ValueError):
            NumChoice.load(b'\xA0\x03\x02\x01\x00\x00', strict=True)
        with self.assertRaises(ValueError):
            NumChoiceOldApi.load(b'\xA0\x03\x02\x01\x00\x00', strict=True)

    def test_choice_parse_return(self):
        nc = NumChoice.load(b'\xA0\x03\x02\x01\x00\x00')
        nc._parsed = None
        self.assertEqual(0, nc.parse().native)

    def test_sequece_choice_choice(self):
        CCSeq({
            'cc': ChoiceChoice(
                'num',
                NumChoice('one', core.Integer(0))
            )
        })

    def test_bit_string_item_access(self):
        named = core.BitString()
        named[0] = True
        self.assertEqual(False, named[2])
        self.assertEqual(False, named[1])
        self.assertEqual(True, named[0])

    @staticmethod
    def mapped_bit_string_info():
        return (
            (
                (0, 1, 1),
                b'\x03\x02\x05\x60',
                set(['one', 'two'])
            ),
            (
                (0,),
                b'\x03\x01\x00',
                set()
            ),
            (
                set(['one', 'two']),
                b'\x03\x02\x05\x60',
                set(['one', 'two'])
            )
        )

    @data('mapped_bit_string_info')
    def mapped_bit_string(self, input_native, der_bytes, native):
        named = NamedBits(input_native)
        self.assertEqual(der_bytes, named.dump())
        self.assertEqual(native, NamedBits.load(der_bytes).native)

    def test_mapped_bit_string_item_access(self):
        named = NamedBits()
        named['one'] = True
        self.assertEqual(False, named['two'])
        self.assertEqual(True, named['one'])
        self.assertEqual(True, 'one' in named.native)

    def test_mapped_bit_string_unset_bit(self):
        named = NamedBits(set(['one', 'two']))
        named['one'] = False
        self.assertEqual(True, named['two'])
        self.assertEqual(set(['two']), named.native)

    def test_mapped_bit_string_sparse(self):
        named = NamedBits((0, 0, 0, 0, 0, 1))
        self.assertEqual(False, named['two'])
        self.assertEqual(True, named[5])
        self.assertEqual(True, 5 in named.native)

    def test_mapped_bit_string_numeric(self):
        named = NamedBits()
        named[1] = True
        self.assertEqual(True, named['one'])
        self.assertEqual(set(['one']), named.native)

    def test_get_sequence_value(self):
        seq = SequenceOfInts([1, 2])
        self.assertEqual(2, seq[1].native)

    def test_replace_sequence_value(self):
        seq = SequenceOfInts([1, 2])
        self.assertEqual([1, 2], seq.native)
        seq[0] = 5
        self.assertEqual([5, 2], seq.native)

    def test_add_to_end_sequence_value(self):
        seq = SequenceOfInts([1, 2])
        self.assertEqual([1, 2], seq.native)
        seq[2] = 5
        self.assertEqual([1, 2, 5], seq.native)
        seq.append(6)
        self.assertEqual([1, 2, 5, 6], seq.native)

    def test_delete_sequence_value(self):
        seq = SequenceOfInts([1, 2])
        self.assertEqual([1, 2], seq.native)
        del seq[0]
        self.assertEqual([2], seq.native)

    def test_sequence_any_asn1value(self):
        seq = SequenceAny()
        seq.append(core.Integer(5))
        self.assertEqual([5], seq.native)

    def test_sequence_any_native_value(self):
        seq = SequenceAny()
        with self.assertRaises(ValueError):
            seq.append(5)

    def test_copy(self):
        a = core.Integer(200)
        b = a.copy()
        self.assertNotEqual(id(a), id(b))
        self.assertEqual(a.contents, b.contents)
        self.assertEqual(a.dump(), b.dump())

    def test_copy_mutable(self):
        a = CopySeq({'name': 'foo', 'pair': {'id': '1.2.3', 'value': 5}})
        # Cache the native representation so it is copied during the copy operation
        a.native
        b = a.copy()
        self.assertNotEqual(id(a), id(b))
        self.assertNotEqual(id(a['pair']), id(b['pair']))
        self.assertEqual(a.contents, b.contents)
        self.assertEqual(a.dump(), b.dump())

        self.assertEqual(a['pair']['value'].native, b['pair']['value'].native)
        a['pair']['value'] = 6
        self.assertNotEqual(a['pair']['value'].native, b['pair']['value'].native)

        a.native['pair']['value'] = 6
        self.assertNotEqual(a.native['pair']['value'], b.native['pair']['value'])

        self.assertNotEqual(a.contents, b.contents)
        self.assertNotEqual(a.dump(), b.dump())

    def test_explicit_tag_header(self):
        val = NumChoice.load(b'\xa0\x03\x02\x01\x00')
        self.assertEqual(b'\xa0\x03\x02\x01', val.chosen._header)
        self.assertEqual(b'\x00', val.chosen.contents)
        val2 = NumChoiceOldApi.load(b'\xa0\x03\x02\x01\x00')
        self.assertEqual(b'\xa0\x03\x02\x01', val2.chosen._header)
        self.assertEqual(b'\x00', val2.chosen.contents)

    def test_explicit_field_default(self):
        val = ExplicitFieldDefault.load(b'\x30\x0f\x03\x02\x06@\xa2\x090\x07\x06\x02*\x03\x02\x01\x01')
        self.assertEqual(set(['one']), val['bits'].native)
        self.assertEqual(
            util.OrderedDict([
                ('id', '1.2.3'),
                ('value', 1)
            ]),
            val['seq'].native
        )

    def test_explicit_header_field_choice(self):
        der = b'\x30\x07\xa0\x05\xa0\x03\x02\x01\x00'
        val = ExplicitField.load(der)
        self.assertEqual(0, val['field'].chosen.native)
        self.assertEqual(der, val.dump(force=True))

        val2 = ExplicitFieldOldApi.load(der)
        self.assertEqual(0, val2['field'].chosen.native)
        self.assertEqual(der, val2.dump(force=True))

    def test_retag(self):
        a = core.Integer(200)
        b = a.retag('explicit', 0)
        self.assertNotEqual(id(a), id(b))
        self.assertEqual(a.contents, b.contents)
        self.assertNotEqual(a.dump(), b.dump())

    def test_untag(self):
        a = core.Integer(200, explicit=0)
        b = a.untag()
        self.assertNotEqual(id(a), id(b))
        self.assertEqual(a.contents, b.contents)
        self.assertNotEqual(a.dump(), b.dump())

    def test_choice_dict_name(self):
        a = CopySeq({'name': 'foo', 'pair': {'id': '1.2.3', 'value': 5}})
        choice = SeqChoice({'one': a})
        self.assertEqual('one', choice.name)

        with self.assertRaises(ValueError):
            SeqChoice({})

        with self.assertRaises(ValueError):
            SeqChoice({'one': a, 'two': a})

        choice2 = SeqChoiceOldApi({'one': a})
        self.assertEqual('one', choice2.name)

        with self.assertRaises(ValueError):
            SeqChoiceOldApi({})

        with self.assertRaises(ValueError):
            SeqChoiceOldApi({'one': a, 'two': a})

    def test_choice_tuple_name(self):
        a = CopySeq({'name': 'foo', 'pair': {'id': '1.2.3', 'value': 5}})
        choice = SeqChoice(('one', a))
        self.assertEqual('one', choice.name)

        with self.assertRaises(ValueError):
            SeqChoice(('one',))

        with self.assertRaises(ValueError):
            SeqChoice(('one', a, None))

        choice2 = SeqChoiceOldApi(('one', a))
        self.assertEqual('one', choice2.name)

        with self.assertRaises(ValueError):
            SeqChoiceOldApi(('one',))

        with self.assertRaises(ValueError):
            SeqChoiceOldApi(('one', a, None))

    def test_load_invalid_choice(self):
        with self.assertRaises(ValueError):
            NumChoice.load(b'\x02\x01\x00')
        with self.assertRaises(ValueError):
            NumChoiceOldApi.load(b'\x02\x01\x00')

    def test_fix_tagging_choice(self):
        correct = core.Integer(200, explicit=2)
        choice = NumChoice(
            name='three',
            value=core.Integer(200, explicit=1)
        )
        self.assertEqual(correct.dump(), choice.dump())
        self.assertEqual(correct.explicit, choice.chosen.explicit)
        choice2 = NumChoiceOldApi(
            name='three',
            value=core.Integer(200, explicit=1)
        )
        self.assertEqual(correct.dump(), choice2.dump())
        self.assertEqual(correct.explicit, choice2.chosen.explicit)

    def test_copy_choice_mutate(self):
        a = CopySeq({'name': 'foo', 'pair': {'id': '1.2.3', 'value': 5}})
        choice = SeqChoice(
            name='one',
            value=a
        )
        choice.dump()
        choice_copy = choice.copy()
        choice.chosen['name'] = 'bar'
        self.assertNotEqual(choice.chosen['name'], choice_copy.chosen['name'])

        choice2 = SeqChoiceOldApi(
            name='one',
            value=a
        )
        choice2.dump()
        choice2_copy = choice2.copy()
        choice2.chosen['name'] = 'bar'
        self.assertNotEqual(choice2.chosen['name'], choice2_copy.chosen['name'])

    def test_dump_ber_indefinite(self):
        # A simple primitive type that is indefinite-length-encoded will be
        # automatically re-encoded to DER encoding
        data = b'\x2C\x80\x0C\x03foo\x00\x00'
        v = core.UTF8String.load(data)
        self.assertEqual(True, v._indefinite)
        self.assertEqual('foo', v.native)
        self.assertEqual(b'\x0C\x03foo', v.dump())

        # In this case the indefinite length items are nested, and the
        # top-level item is fixed-length, so it won't get automatically
        # re-encoded
        data = b'\x30\x0d\x30\x80\x2C\x80\x0C\x03foo\x00\x00\x00\x00'
        v = NestedUTF8Sequence.load(data)
        self.assertEqual(data, v.dump())

        # Here both the top-level and the nested encoding will get fixed since
        # the top-level being indefinitely triggers a full re-encoding
        data = b'\x30\x80\x30\x09\x2C\x80\x0C\x03foo\x00\x00\x00\x00'
        v = NestedUTF8Sequence.load(data)
        self.assertEqual(b'\x30\x07\x30\x05\x0C\x03foo', v.dump())

    def test_copy_indefinite(self):
        v = core.BitString.load(b'\x23\x80\x03\x02\x00\x04\x00\x00')
        self.assertEqual(True, v._indefinite)
        v2 = v.copy()
        self.assertEqual(0, v2.method)
        self.assertEqual(3, v2.tag)
        self.assertEqual(False, v2._indefinite)
        self.assertEqual((0, 0, 0, 0, 0, 1, 0, 0), v2.native)
        self.assertEqual(b'\x03\x02\x00\x04', v2.dump())

        v = core.OctetBitString.load(b'\x23\x80\x03\x02\x00\x04\x00\x00')
        self.assertEqual(True, v._indefinite)
        v2 = v.copy()
        self.assertEqual(0, v2.method)
        self.assertEqual(3, v2.tag)
        self.assertEqual(False, v2._indefinite)
        self.assertEqual(b'\x04', v2.native)
        self.assertEqual(b'\x03\x02\x00\x04', v2.dump())

        v = core.ParsableOctetBitString.load(b'\x23\x80\x03\x04\x00\x02\x01\x04\x00\x00')
        self.assertEqual(4, v.parsed.native)
        self.assertEqual(True, v._indefinite)
        v2 = v.copy()
        self.assertEqual(0, v2.method)
        self.assertEqual(3, v2.tag)
        self.assertEqual(False, v2._indefinite)
        self.assertEqual(4, v2.parsed.native)
        self.assertEqual(b'\x03\x04\x00\x02\x01\x04', v2.dump())

        v = core.IntegerBitString.load(b'\x23\x80\x03\x02\x00\x04\x00\x00')
        self.assertEqual(True, v._indefinite)
        v2 = v.copy()
        self.assertEqual(0, v2.method)
        self.assertEqual(3, v2.tag)
        self.assertEqual(False, v2._indefinite)
        self.assertEqual(4, v2.native)
        self.assertEqual(b'\x03\x02\x00\x04', v2.dump())

        v = core.OctetString.load(b'\x24\x80\x04\x03foo\x00\x00')
        self.assertEqual(True, v._indefinite)
        v2 = v.copy()
        self.assertEqual(0, v2.method)
        self.assertEqual(4, v2.tag)
        self.assertEqual(False, v2._indefinite)
        self.assertEqual(b'foo', v2.native)
        self.assertEqual(b'\x04\x03foo', v2.dump())

        v = core.IntegerOctetString.load(b'\x24\x80\x04\x01\x04\x00\x00')
        self.assertEqual(True, v._indefinite)
        v2 = v.copy()
        self.assertEqual(0, v2.method)
        self.assertEqual(4, v2.tag)
        self.assertEqual(False, v2._indefinite)
        self.assertEqual(4, v2.native)
        self.assertEqual(b'\x04\x01\x04', v2.dump())

        v = core.ParsableOctetString.load(b'\x24\x80\x04\x03\x02\x01\x04\x00\x00')
        self.assertEqual(4, v.parsed.native)
        self.assertEqual(True, v._indefinite)
        v2 = v.copy()
        self.assertEqual(0, v2.method)
        self.assertEqual(4, v2.tag)
        self.assertEqual(False, v2._indefinite)
        self.assertEqual(4, v2.parsed.native)
        self.assertEqual(b'\x02\x01\x04', v2.__bytes__())
        self.assertEqual(b'\x04\x03\x02\x01\x04', v2.dump())

        v = core.UTF8String.load(b'\x2C\x80\x0C\x03foo\x00\x00')
        self.assertEqual(True, v._indefinite)
        v2 = v.copy()
        self.assertEqual(0, v2.method)
        self.assertEqual(12, v2.tag)
        self.assertEqual(False, v2._indefinite)
        self.assertEqual('foo', v2.native)
        self.assertEqual(b'\x0C\x03foo', v2.dump())

    def test_concat(self):
        child1 = Seq({
            'id': '1.2.3',
            'value': 1
        })
        child2 = core.Integer(0)
        parent = ConcatTest([
            child1,
            child2
        ])
        self.assertEqual(child1, parent[0])
        self.assertEqual(child2, parent[1])
        self.assertEqual(child1.dump() + child2.dump(), parent.dump())

    def test_oid_map_unmap(self):
        self.assertEqual('abc', MyOids.map('1.2.3'))
        self.assertEqual('def', MyOids.map('4.5.6'))
        self.assertEqual('7.8.9', MyOids.map('7.8.9'))
        self.assertEqual('1.2.3', MyOids.unmap('abc'))
        self.assertEqual('4.5.6', MyOids.unmap('def'))
        self.assertEqual('7.8.9', MyOids.unmap('7.8.9'))

        with self.assertRaises(ValueError):
            MyOids.unmap('no_such_mapping')

    def test_oid_dotted_native(self):
        self.assertEqual('abc', MyOids('1.2.3').native)
        self.assertEqual('1.2.3', MyOids('1.2.3').dotted)
        self.assertEqual('abc', MyOids('abc').native)
        self.assertEqual('1.2.3', MyOids('abc').dotted)

    def test_dump_set(self):
        st = SetTest({'two': 2, 'one': 1})
        self.assertEqual(b'1\x06\x81\x01\x01\x82\x01\x02', st.dump())

    def test_dump_set_of(self):
        st = SetOfTest([3, 2, 1])
        self.assertEqual(b'1\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03', st.dump())

    def test_indefinite_length_octet_string(self):
        data = b'$\x80\x04\x02\x01\x01\x04\x01\x01\x00\x00'
        a = core.OctetString.load(data)
        self.assertEqual(b'\x01\x01\x01', a.native)
        self.assertEqual(b'\x01\x01\x01', a.__bytes__())
        self.assertEqual(1, a.method)
        # Test copying moves internal state
        self.assertEqual(a._bytes, a.copy()._bytes)

    def test_indefinite_length_octet_string_2(self):
        data = b'$\x80\x04\r\x8d\xff\xf0\x98\x076\xaf\x93nB:\xcf\xcc\x04\x15' \
            b'\x92w\xf7\xf0\xe4y\xff\xc7\xdc3\xb2\xd0={\x1a\x18mDr\xaaI\x00\x00'
        a = core.OctetString.load(data)
        self.assertEqual(
            b'\x8d\xff\xf0\x98\x076\xaf\x93nB:\xcf\xcc\x92w\xf7\xf0\xe4y\xff\xc7\xdc3\xb2\xd0={\x1a\x18mDr\xaaI',
            a.native
        )

    def test_nested_indefinite_length_octet_string(self):
        data = b'\x24\x80\x24\x80\x24\x80\x04\x00\x00\x00\x00\x00\x00\x00'
        a = core.load(data)
        self.assertEqual(b'', a.native)
        self.assertEqual(b'', a.__bytes__())
        self.assertEqual(1, a.method)
        self.assertEqual(b'\x04\x00', a.dump(force=True))
        # Test copying moves internal state
        self.assertEqual(a._bytes, a.copy()._bytes)

    def test_indefinite_length_integer_octet_string(self):
        data = b'$\x80\x04\x02\x01\x01\x04\x01\x01\x00\x00'
        a = core.IntegerOctetString.load(data)
        self.assertEqual(65793, a.native)
        self.assertEqual(1, a.method)
        self.assertEqual(b'\x01\x01\x01', a.cast(core.OctetString).native)

    def test_indefinite_length_parsable_octet_string(self):
        data = b'$\x80\x04\x02\x04\x01\x04\x01\x01\x00\x00'
        a = core.ParsableOctetString.load(data)
        self.assertEqual(b'\x04\x01\x01', a.parsed.dump())
        self.assertEqual(b'\x04\x01\x01', a.__bytes__())
        self.assertEqual(1, a.method)
        self.assertEqual(b'\x01', a.parsed.native)
        self.assertEqual(b'\x01', a.native)
        self.assertEqual(b'\x04\x01\x01', a.cast(core.OctetString).native)
        # Test copying moves internal state
        self.assertEqual(a._bytes, a.copy()._bytes)
        self.assertEqual(a._parsed, a.copy()._parsed)

    def test_indefinite_length_utf8string(self):
        data = b'\x2C\x80\x0C\x02\x61\x62\x0C\x01\x63\x00\x00'
        a = core.UTF8String.load(data)
        self.assertEqual('abc', a.native)
        self.assertEqual('abc', a.__unicode__())
        self.assertEqual(1, a.method)
        # Ensure a forced re-encoding is proper DER
        self.assertEqual(b'\x0C\x03\x61\x62\x63', a.dump(force=True))
        # Test copying moves internal state
        self.assertEqual(a._unicode, a.copy()._unicode)

    def test_indefinite_length_bit_string(self):
        data = b'#\x80\x03\x02\x00\x01\x03\x02\x02\x04\x00\x00'
        a = core.BitString.load(data)
        self.assertEqual((0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1), a.native)
        self.assertEqual((0, 0), a.unused_bits)

        # Example from X.690 §8.6.4.2
        prim = core.BitString.load(b'\x03\x07\x04\x0A\x3B\x5F\x29\x1C\xD0')
        self.assertEqual((0, 0, 0, 0), prim.unused_bits)
        indef = core.BitString.load(b'\x23\x80\x03\x03\x00\x0a\x3b\x03\x05\x04\x5f\x29\x1c\xd0\x00\x00')
        self.assertEqual(prim.native, indef.native)
        self.assertEqual(core._int_to_bit_tuple(0x0A3B5F291CD, 44), indef.native)
        self.assertEqual((0, 0, 0, 0), indef.unused_bits)

        unused = core.BitString.load(b'\x23\x80\x03\x03\x00\x0a\x3b\x03\x05\x04\x5f\x29\x1c\xdd\x00\x00')
        self.assertEqual(indef.native, unused.native)
        self.assertEqual((1, 1, 0, 1), unused.unused_bits)

        unused.set(indef.native)
        self.assertEqual(indef.native, unused.native)
        self.assertEqual((0, 0, 0, 0), unused.unused_bits)

    def test_integer_bit_string(self):
        a = core.IntegerBitString.load(b'\x03\x02\x04\xcb')
        self.assertEqual(12, a.native)
        self.assertEqual((1, 0, 1, 1), a.unused_bits)

        b = a.copy()
        self.assertEqual(12, b.native)
        self.assertEqual((1, 0, 1, 1), b.unused_bits)

        a.set(56)
        self.assertEqual((), a.unused_bits)
        self.assertEqual(56, a.native)
        self.assertEqual(b'\x03\x02\x00\x38', a.dump())

        with self.assertRaises(TypeError):
            a.set('badtype')

        with self.assertRaises(ValueError):
            core.IntegerBitString(-1)

    def test_indefinite_length_integer_bit_string(self):
        data = b'#\x80\x03\x02\x00\x01\x03\x02\x00\x04\x00\x00'
        a = core.IntegerBitString.load(data)
        self.assertEqual(260, a.native)
        self.assertEqual((), a.unused_bits)

        a = core.IntegerBitString.load(b'\x23\x80\x00\x00')
        self.assertEqual(0, a.native)
        self.assertEqual((), a.unused_bits)

        a = core.IntegerBitString.load(b'\x23\x80\x03\x01\x00\x03\x03\x03\x03\x03\x00\x00')
        self.assertEqual(96, a.native)
        self.assertEqual((0, 1, 1), a.unused_bits)

        a.set(56)
        self.assertEqual((), a.unused_bits)
        self.assertEqual(56, a.native)
        self.assertEqual(b'\x03\x02\x00\x38', a.dump())

    @data('bit_string_error_values')
    def integer_bit_string_errors(self, enc_bytes):
        with self.assertRaises(ValueError):
            core.IntegerBitString.load(enc_bytes).native

    def test_octet_bit_string(self):
        a = core.OctetBitString.load(b'\x03\x02\x04\xcb')
        self.assertEqual(b'\xc0', a.native)
        self.assertEqual((1, 0, 1, 1), a.unused_bits)

        a.set(b'\x38')
        self.assertEqual((), a.unused_bits)
        self.assertEqual(b'\x38', a.native)
        self.assertEqual(b'\x03\x02\x00\x38', a.dump())

        with self.assertRaises(TypeError):
            a.set('badtype')

    def test_indefinite_length_octet_bit_string(self):
        data = b'#\x80\x03\x02\x00\x01\x03\x02\x00\x04\x00\x00'
        a = core.OctetBitString.load(data)
        self.assertEqual(b'\x01\x04', a.native)
        self.assertEqual(b'\x01\x04', a.__bytes__())
        # Test copying moves internal state
        self.assertEqual(a._bytes, a.copy()._bytes)

        # octet bit string with unused bits
        a = core.OctetBitString.load(b'\x23\x80\x03\x05\x05\x74\x65\x73\x74\x00\x00')
        self.assertEqual(b'\x74\x65\x73\x60', a.native)
        self.assertEqual((1, 0, 1, 0, 0), a.unused_bits)

        a.set(b'\x38')
        self.assertEqual((), a.unused_bits)
        self.assertEqual(b'\x38', a.native)
        self.assertEqual(b'\x03\x02\x00\x38', a.dump())

    @data('bit_string_error_values')
    def octet_bit_string_errors(self, enc_bytes):
        with self.assertRaises(ValueError):
            core.OctetBitString.load(enc_bytes).native

    def test_indefinite_length_parsable_octet_bit_string(self):
        data = b'#\x80\x03\x03\x00\x0C\x02\x03\x03\x00\x61\x62\x00\x00'
        a = core.ParsableOctetBitString.load(data)
        self.assertEqual(b'\x0C\x02\x61\x62', a.parsed.dump())
        self.assertEqual(b'\x0C\x02\x61\x62', a.__bytes__())
        self.assertEqual('ab', a.parsed.native)
        self.assertEqual('ab', a.native)
        # Test copying moves internal state
        self.assertEqual(a._bytes, a.copy()._bytes)
        self.assertEqual(a._parsed, a.copy()._parsed)

        with self.assertRaises(ValueError):
            # parsable octet bit string with unused bits
            core.ParsableOctetBitString.load(b'\x23\x80\x03\x03\x04\x02\x00\x03\x03\x04\x12\xa0\x00\x00').native

    def test_integer_octet_string(self):
        v = core.IntegerOctetString(10)
        self.assertEqual(10, v.native)

        with self.assertRaises(TypeError):
            core.IntegerOctetString('0')

        with self.assertRaises(ValueError):
            core.IntegerOctetString(-1)

    def test_explicit_application_tag(self):
        data = b'\x6a\x81\x03\x02\x01\x00'
        ati = ApplicationTaggedInteger.load(data)

        self.assertEqual(((1, 10),), ati.explicit)
        self.assertEqual(0, ati.class_)
        self.assertEqual(2, ati.tag)
        self.assertEqual(0, ati.native)

        # The output encoding is DER, whereas the input was not, so
        # the length encoding changes from long form to short form
        self.assertEqual(b'\x6a\x03\x02\x01\x00', ati.dump(force=True))

    def test_required_field(self):
        with self.assertRaisesRegex(ValueError, '"id" is missing from structure'):
            Seq({'value': core.Integer(5)}).dump()

    def test_explicit_application_tag_nested(self):
        # tag = [APPLICATION 10] constructed; length = 18
        #   OUTER SEQUENCE: tag = [UNIVERSAL 16] constructed; length = 16
        #     outernumber : tag = [11] constructed; length = 3
        #       INTEGER: tag = [UNIVERSAL 2] primitive; length = 1
        #         23
        #     inner : tag = [12] constructed; length = 9
        #       tag = [APPLICATION 20] constructed; length = 7
        #         INNER SEQUENCE: tag = [UNIVERSAL 16] constructed; length = 5
        #           innernumber : tag = [21] constructed; length = 3
        #             INTEGER: tag = [UNIVERSAL 2] primitive; length = 1
        #               42
        der = (
            b'\x6A\x12\x30\x10\xAB\x03\x02\x01\x17\xAC\x09\x74'
            b'\x07\x30\x05\xB5\x03\x02\x01\x2A'
        )

        ato = ApplicationTaggedOuter.load(der)
        self.assertEqual(((1, 10),), ato.explicit)
        self.assertEqual(0, ato.class_)
        self.assertEqual(16, ato.tag)
        self.assertEqual(1, ato.method)

        onum = ato['outernumber']
        self.assertEqual(((2, 11),), onum.explicit)
        self.assertEqual(0, onum.class_)
        self.assertEqual(2, onum.tag)
        self.assertEqual(0, onum.method)
        self.assertEqual(23, onum.native)

        ati = ato['inner']
        self.assertEqual(((1, 20), (2, 12)), ati.explicit)
        self.assertEqual(0, ati.class_)
        self.assertEqual(16, ati.tag)
        self.assertEqual(util.OrderedDict([('innernumber', 42)]), ati.native)

        inum = ati['innernumber']
        self.assertEqual(((2, 21),), inum.explicit)
        self.assertEqual(0, inum.class_)
        self.assertEqual(2, inum.tag)
        self.assertEqual(0, inum.method)
        self.assertEqual(42, inum.native)

        self.assertEqual(der, ato.dump(force=True))

    def test_sequence_choice_field_by_tuple(self):
        val = ExplicitField({'field': ('one', 32)})
        self.assertEqual('one', val['field'].name)
        self.assertEqual(32, val['field'].chosen.native)

    def test_sequence_choice_field_by_dict(self):
        val = ExplicitField({'field': {'two': 32}})
        self.assertEqual('two', val['field'].name)
        self.assertEqual(32, val['field'].chosen.native)

    def test_nested_explicit_tag_choice(self):
        # Explicitly tagged values have a _header that contains
        # the explicit tag and the header for the contained value.
        # When parsing nested Choice values, it is necessary to not pull
        # up the next Choice value's header, since Choice values
        # themselves don't have their own header and it will result in
        # duplication.
        data = b'\x30\x09\x03\x01\x00\xa0\x04\xa2\x02\x80\x00'
        image_data = SpcPeImageData.load(data, strict=True)
        self.assertEqual(data[2:5],  image_data['flags'].dump())
        self.assertEqual(data[5:11],  image_data['file'].dump())
        self.assertEqual(data[5:7],  image_data['file']._header)
        self.assertEqual(data[7:11],  image_data['file'].chosen.dump())
        self.assertEqual(data[7:9],  image_data['file'].chosen._header)
        self.assertEqual(data[9:11],  image_data['file'].chosen.chosen.dump())
        self.assertEqual(data[9:11],  image_data['file'].chosen.chosen._header)

        image_data2 = SpcPeImageData.load(data, strict=True)
        self.assertEqual(data[2:5],  image_data2['flags'].dump(True))
        self.assertEqual(data[5:11],  image_data2['file'].dump(True))
        self.assertEqual(data[5:7],  image_data2['file']._header)
        self.assertEqual(data[7:11],  image_data2['file'].chosen.dump(True))
        self.assertEqual(data[7:9],  image_data2['file'].chosen._header)
        self.assertEqual(data[9:11],  image_data2['file'].chosen.chosen.dump(True))
        self.assertEqual(data[9:11],  image_data2['file'].chosen.chosen._header)

    def test_choice_dump_header_native(self):
        s = SpcString({'unicode': 'test'})
        self.assertEqual(b'\x80\x08\x00t\x00e\x00s\x00t', s.dump())
        self.assertEqual(b'', s._header)
        self.assertEqual('test', s.native)
        self.assertEqual(b'\x80\x08', s.chosen._header)
        self.assertEqual('test', s.chosen.native)

        link = SpcLink('file', {'unicode': 'test'})
        self.assertEqual(b'\xa2\x0a\x80\x08\x00t\x00e\x00s\x00t', link.dump())
        self.assertEqual(b'', link._header)
        self.assertEqual('test', link.native)
        self.assertEqual(b'\xa2\x0a', link.chosen._header)
        self.assertEqual('test', link.chosen.native)
        self.assertEqual(b'\x80\x08', link.chosen.chosen._header)
        self.assertEqual('test', link.chosen.chosen.native)

    def test_parse_broken_sequence_fields_repeatedly(self):
        s = Seq.load(b'\x30\x06\x88\x00\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            s.native
        with self.assertRaises(ValueError):
            s.native

    def test_parse_broken_sequenceof_children_repeatedly(self):
        s = SequenceOfInts.load(b'\x30\x06\x88\x00\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            s.native
        with self.assertRaises(ValueError):
            s.native

    def test_wrong_asn1value(self):
        with self.assertRaises(TypeError):
            Seq({
                'id': core.Integer(1),
                'value': 1
            })

    def test_wrong_asn1value2(self):
        with self.assertRaises(TypeError):
            CopySeq({
                'name': core.UTF8String('Test'),
                'pair': core.Integer(1)
            })

    def test_wrong_asn1value3(self):
        with self.assertRaises(TypeError):
            NestSeqAny({
                'id': '2.3.4.5',
                'value': core.Integer(1)
            })

    def test_wrong_asn1value4(self):
        with self.assertRaises(TypeError):
            NestSeqExplicit({
                'id': '2.3.4.5',
                'value': core.Integer(1)
            })

    def test_integer_octet_string_encoded_width(self):
        a = core.IntegerOctetString(1)
        self.assertEqual(1, a.native)
        self.assertEqual(b'\x04\x01\x01', a.dump())

        b = core.IntegerOctetString(1)
        b.set_encoded_width(4)
        self.assertEqual(1, b.native)
        self.assertEqual(b'\x04\x04\x00\x00\x00\x01', b.dump())

    @staticmethod
    def object_identifier_info():
        return (
            ("0.0", b"\x06\x01\x00"),
            ("0.39", b"\x06\x01\x27"),
            ("1.0", b"\x06\x01\x28"),
            ("1.39", b"\x06\x01\x4f"),
            ("2.0", b"\x06\x01\x50"),
            ("2.39", b"\x06\x01\x77"),
            ("2.100.3", b"\x06\x03\x81\x34\x03"),
            ("2.16.840.1.113730.1.1", b"\x06\x09\x60\x86\x48\x01\x86\xf8\x42\x01\x01"),
        )

    @data('object_identifier_info')
    def object_identifier(self, native, der_bytes):
        oid = core.ObjectIdentifier(native)
        self.assertEqual(der_bytes, oid.dump())
        self.assertEqual(native, core.ObjectIdentifier.load(der_bytes).native)

    def test_broken_object_identifier(self):
        with self.assertRaisesRegex(ValueError, "First arc must be "):
            core.ObjectIdentifier("3.4.5")

        with self.assertRaisesRegex(ValueError, "Second arc must be "):
            core.ObjectIdentifier("1.100.1000")

        with self.assertRaisesRegex(ValueError, "Second arc must be "):
            core.ObjectIdentifier("0.40")
