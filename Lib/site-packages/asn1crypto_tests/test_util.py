# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os
from datetime import date, datetime, time, timedelta

from asn1crypto import util

from .unittest_data import data_decorator
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    py2 = True
    byte_cls = str
    num_cls = long  # noqa
else:
    py2 = False
    byte_cls = bytes
    num_cls = int


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')
utc = util.timezone.utc


@data_decorator
class UtilTests(unittest.TestCase):

    def test_int_to_bytes(self):
        self.assertEqual(util.int_to_bytes(0, False, 0), b'')
        self.assertEqual(util.int_to_bytes(0, False), b'\x00')
        self.assertEqual(util.int_to_bytes(0, False, 3), b'\x00\x00\x00')
        self.assertEqual(util.int_to_bytes(0, True, 0), b'')
        self.assertEqual(util.int_to_bytes(0, True), b'\x00')
        self.assertEqual(util.int_to_bytes(0, True, 3), b'\x00\x00\x00')

        self.assertEqual(util.int_to_bytes(128, False), b'\x80')
        self.assertEqual(util.int_to_bytes(128, False, 3), b'\x00\x00\x80')
        self.assertEqual(util.int_to_bytes(-128, True), b'\x80')
        self.assertEqual(util.int_to_bytes(-128, True, 3), b'\xff\xff\x80')

        self.assertEqual(util.int_to_bytes(255, False), b'\xff')
        self.assertEqual(util.int_to_bytes(255, False, 3), b'\x00\x00\xff')
        self.assertEqual(util.int_to_bytes(-1, True), b'\xff')
        self.assertEqual(util.int_to_bytes(-1, True, 3), b'\xff\xff\xff')

        self.assertEqual(util.int_to_bytes(12345678, False), b'\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678, False, 3), b'\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678, False, 5), b'\x00\x00\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678 - 2 ** 24, True), b'\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678 - 2 ** 24, True, 3), b'\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678 - 2 ** 24, True, 5), b'\xff\xff\xbc\x61\x4e')

        with self.assertRaises(OverflowError):
            util.int_to_bytes(123456789, width=3)
        with self.assertRaises(OverflowError):
            util.int_to_bytes(50000, signed=True, width=2)

    def test_int_from_bytes(self):
        self.assertEqual(util.int_from_bytes(b'', False), 0)
        self.assertEqual(util.int_from_bytes(b'', True), 0)
        self.assertEqual(util.int_from_bytes(b'\x00', False), 0)
        self.assertEqual(util.int_from_bytes(b'\x00', True), 0)
        self.assertEqual(util.int_from_bytes(b'\x80', False), 128)
        self.assertEqual(util.int_from_bytes(b'\x80', True), -128)
        self.assertEqual(util.int_from_bytes(b'\xff', False), 255)
        self.assertEqual(util.int_from_bytes(b'\xff', True), -1)
        self.assertEqual(util.int_from_bytes(b'\xbc\x61\x4e', False), 12345678)
        self.assertEqual(util.int_from_bytes(b'\xbc\x61\x4e', True), 12345678 - 2 ** 24)

    def test_int_fromto_bytes(self):
        for i in range(-300, 301):
            self.assertEqual(i, util.int_from_bytes(util.int_to_bytes(i, True), True))
        for i in range(0, 301):
            self.assertEqual(i, util.int_from_bytes(util.int_to_bytes(i, False), False))

    def test_timezone(self):
        delta_plus_5_42 = timedelta(hours=5, minutes=42)
        delta_minus_5_42 = -delta_plus_5_42

        # limited to +24h
        with self.assertRaises(ValueError):
            util.timezone(delta_plus_5_42 * 5)

        # limited to -24h
        with self.assertRaises(ValueError):
            util.timezone(delta_minus_5_42 * 5)

        # py2 implementation supports no sub-minutes time zones
        if py2:
            with self.assertRaises(ValueError):
                util.timezone(timedelta(hours=5, minutes=42, seconds=13))

            with self.assertRaises(ValueError):
                util.timezone(timedelta(hours=5, minutes=42, microseconds=13))

        # test __eq__
        tz0 = util.timezone(delta_plus_5_42)
        tz1 = util.timezone(delta_minus_5_42)
        self.assertEqual(tz0, tz0)
        self.assertEqual(tz1, tz1)
        self.assertNotEqual(tz0, tz1)
        self.assertFalse(tz0 == "not equal to a str")

        # test tzname
        self.assertEqual('5_42', util.timezone(delta_plus_5_42, '5_42').tzname(None))
        self.assertEqual('UTC+05:42', util.timezone(delta_plus_5_42).tzname(None))
        self.assertEqual('UTC-05:42', util.timezone(delta_minus_5_42).tzname(None))
        if py2 or sys.version_info >= (3, 6):
            # bpo22241
            self.assertEqual('UTC', util.timezone(timedelta(0)).tzname(None))

        # test utcoffset
        self.assertEqual(delta_minus_5_42, util.timezone(delta_minus_5_42).utcoffset(None))

        # test dst
        self.assertTrue(util.timezone(delta_minus_5_42).dst(None) in set((timedelta(0), None)))

        # test create_timezone
        self.assertTrue(util.create_timezone(delta_plus_5_42) is util.create_timezone(timedelta(hours=5, minutes=42)))
        self.assertFalse(util.create_timezone(delta_plus_5_42) is util.create_timezone(delta_minus_5_42))

    def test_utc_with_dst(self):
        self.assertEqual('UTC', util.utc_with_dst.tzname(None))

    def test_extended_date_strftime(self):
        self.assertEqual('0000-01-01', util.extended_date(0, 1, 1).strftime('%Y-%m-%d'))
        self.assertEqual('Sat Saturday Jan January', util.extended_date(0, 1, 1).strftime('%a %A %b %B'))
        self.assertEqual('Tue Tuesday Feb February 29', util.extended_date(0, 2, 29).strftime('%a %A %b %B %d'))
        if sys.platform == 'win32' and sys.version_info < (3, 5):
            self.assertEqual('01/01/00 00:00:00', util.extended_date(0, 1, 1).strftime('%c'))
        else:
            self.assertEqual('Sat Jan  1 00:00:00 0000', util.extended_date(0, 1, 1).strftime('%c'))
        self.assertEqual('01/01/00', util.extended_date(0, 1, 1).strftime('%x'))

    def test_extended_datetime_init(self):
        with self.assertRaises(ValueError):
            util.extended_datetime(2000, 11, 27)

    def test_extended_date_init(self):
        with self.assertRaises(ValueError):
            util.extended_date(2000, 11, 27)

    def test_extended_datetime_properties(self):
        zone = util.create_timezone(timedelta(hours=12, minutes=45))
        dt = util.extended_datetime(0, 11, 27, 5, 44, 31, 14889, zone)
        self.assertEqual(dt.year, 0)
        self.assertEqual(dt.month, 11)
        self.assertEqual(dt.day, 27)
        self.assertEqual(dt.hour, 5)
        self.assertEqual(dt.minute, 44)
        self.assertEqual(dt.second, 31)
        self.assertEqual(dt.microsecond, 14889)
        self.assertEqual(dt.tzinfo, zone)

    def test_extended_date_properties(self):
        ext_date = util.extended_date(0, 11, 27)
        self.assertEqual(ext_date.year, 0)
        self.assertEqual(ext_date.month, 11)
        self.assertEqual(ext_date.day, 27)

    def test_extended_datetime_isoformat(self):
        self.assertEqual('0000-01-01T00:00:00', util.extended_datetime(0, 1, 1).isoformat())
        self.assertEqual('0000-01-01T00:00:00.001000', util.extended_datetime(0, 1, 1, microsecond=1000).isoformat())
        self.assertEqual('0000-01-01%00:00:00', util.extended_datetime(0, 1, 1).isoformat(sep='%'))

    def test_extended_date_isoformat(self):
        self.assertEqual('0000-01-01', util.extended_date(0, 1, 1).isoformat())
        self.assertEqual('0000-11-27', util.extended_date(0, 11, 27).isoformat())

    def test_extended_datetime_strftime(self):
        self.assertEqual('0000-01-01 00:00:00', util.extended_datetime(0, 1, 1).strftime('%Y-%m-%d %H:%M:%S'))
        self.assertEqual('Sat Saturday Jan January', util.extended_datetime(0, 1, 1).strftime('%a %A %b %B'))
        self.assertEqual('Tue Tuesday Feb February 29', util.extended_datetime(0, 2, 29).strftime('%a %A %b %B %d'))
        if sys.platform == 'win32' and sys.version_info < (3, 5):
            self.assertEqual('01/01/00 00:00:00', util.extended_datetime(0, 1, 1).strftime('%c'))
        else:
            self.assertEqual('Sat Jan  1 00:00:00 0000', util.extended_datetime(0, 1, 1).strftime('%c'))
        self.assertEqual('01/01/00', util.extended_datetime(0, 1, 1).strftime('%x'))
        self.assertEqual('%Y', util.extended_datetime(0, 1, 1).strftime('%%Y'))

    def test_extended_datetime_replace(self):
        zone = util.create_timezone(timedelta(hours=12, minutes=45))
        ext_dt = util.extended_datetime(0, 1, 1, 23, tzinfo=zone)
        self.assertEqual(ext_dt.replace(year=2040, minute=59), datetime(2040, 1, 1, 23, 59, tzinfo=zone))
        self.assertEqual(ext_dt.replace(minute=59), util.extended_datetime(0, 1, 1, 23, 59, tzinfo=zone))

    def test_extended_date_replace(self):
        ext_date = util.extended_date(0, 2, 27)
        self.assertEqual(ext_date.replace(year=2040), date(2040, 2, 27))
        self.assertEqual(ext_date.replace(day=29), util.extended_date(0, 2, 29))
        with self.assertRaises(ValueError):
            ext_date.replace(day=30)

    def test_extended_datetime_encodings(self):
        zone = util.create_timezone(timedelta(hours=12, minutes=45))

        # test with microseconds
        ext_dt = util.extended_datetime(0, 2, 29, 9, 17, 45, 14889, zone)
        self.assertEqual(str(ext_dt), '0000-02-29 09:17:45.014889+12:45')
        if py2:
            self.assertEqual(unicode(ext_dt), '0000-02-29 09:17:45.014889+12:45')  # noqa: F821

        # test without microseconds
        ext_dt = util.extended_datetime(0, 2, 29, 9, 17, 45, 0, zone)
        self.assertEqual(str(ext_dt), '0000-02-29 09:17:45+12:45')
        if py2:
            self.assertEqual(unicode(ext_dt), '0000-02-29 09:17:45+12:45')  # noqa: F821

    def test_extended_date_encodings(self):
        ext_date = util.extended_date(0, 2, 29)
        self.assertEqual(str(ext_date), '0000-02-29')
        if py2:
            self.assertEqual(unicode(ext_date), '0000-02-29')  # noqa: F821

    def test_extended_datetime_timestamp(self):
        if sys.version_info >= (3, 3):
            zone = util.create_timezone(timedelta(hours=12, minutes=45))
            ext_dt = util.extended_datetime(0, 12, 31, 23, 0, 0, 14889, zone)
            dt = datetime(1, 1, 1, 0, 0, 0, 14889, zone)
            self.assertTrue(abs(dt.timestamp() - ext_dt.timestamp() - 3600.0) < 0.0000001)

    def test_extended_date_compare(self):
        self.assertTrue(util.extended_date(0, 1, 1) < date(1, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) <= date(1, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) != date(1, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) == date(1, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) >= date(1, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) > date(1, 1, 1))

        self.assertFalse(util.extended_date(0, 1, 1) < util.extended_date(0, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) <= util.extended_date(0, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) != util.extended_date(0, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) == util.extended_date(0, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) >= util.extended_date(0, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) > util.extended_date(0, 1, 1))

        self.assertTrue(util.extended_date(0, 1, 1) < util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 1) <= util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 1) != util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 1) == util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 1) >= util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 1) > util.extended_date(0, 1, 2))

        self.assertFalse(util.extended_date(0, 1, 3) < util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 3) <= util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 3) != util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 3) == util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 3) >= util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 3) > util.extended_date(0, 1, 2))

        with self.assertRaises(TypeError):
            util.extended_date(0, 1, 1) < "0000-01-02"

    def test_extended_datetime_compare(self):
        self.assertTrue(util.extended_datetime(0, 1, 1) < datetime(1, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) <= datetime(1, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) != datetime(1, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) == datetime(1, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) >= datetime(1, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) > datetime(1, 1, 1))

        self.assertFalse(util.extended_datetime(0, 1, 1) < util.extended_datetime(0, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) <= util.extended_datetime(0, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) != util.extended_datetime(0, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) == util.extended_datetime(0, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) >= util.extended_datetime(0, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) > util.extended_datetime(0, 1, 1))

        self.assertTrue(util.extended_datetime(0, 1, 1) < util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 1) <= util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 1) != util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 1) == util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 1) >= util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 1) > util.extended_datetime(0, 1, 2))

        self.assertFalse(util.extended_datetime(0, 1, 3) < util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 3) <= util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 3) != util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 3) == util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 3) >= util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 3) > util.extended_datetime(0, 1, 2))
        self.assertTrue(
            util.extended_datetime(0, 12, 31, 21, 4, 5, 6, util.create_timezone(timedelta(hours=-8)))
            == datetime(1, 1, 1, 5, 4, 5, 6, utc)
        )
        self.assertTrue(
            util.extended_datetime(0, 12, 31, 21, 4, 5, 6, util.create_timezone(timedelta(hours=-8)))
            == datetime(1, 1, 1, 5, 7, 5, 6, util.create_timezone(timedelta(hours=0, minutes=3)))
        )
        self.assertFalse(
            util.extended_datetime(0, 12, 31, 21, 4, 5, 6, util.create_timezone(timedelta(hours=-7)))
            == datetime(1, 1, 1, 5, 4, 5, 6, utc)
        )
        self.assertFalse(util.extended_datetime(0, 1, 1) == util.extended_datetime(0, 1, 1, tzinfo=utc))
        self.assertFalse(util.extended_datetime(0, 1, 1) == "0000-01-01")

        with self.assertRaises(TypeError):
            util.extended_datetime(0, 1, 1) < "0000-01-02"

    def test_extended_datetime_arithmetic(self):
        zone = util.create_timezone(timedelta(hours=12, minutes=45))
        ext_dt = util.extended_datetime(0, 12, 31, 9, 17, 45, 14889, zone)
        self.assertEqual(ext_dt + timedelta(hours=20), datetime(1, 1, 1, 5, 17, 45, 14889, zone))
        self.assertEqual(ext_dt - timedelta(hours=20), util.extended_datetime(0, 12, 30, 13, 17, 45, 14889, zone))
        self.assertEqual(ext_dt - ext_dt, timedelta(0))

        zone2 = util.create_timezone(timedelta(hours=-8, minutes=-31))
        ext_dt2 = util.extended_datetime(0, 11, 14, 13, 44, 20, 876543, zone2)
        expected_diff = timedelta(days=47, hours=-4, minutes=-27, seconds=25, microseconds=-861654)
        expected_diff -= timedelta(hours=20, minutes=76)
        self.assertEqual(ext_dt - ext_dt2, expected_diff)

        dt = datetime(400, 12, 31, 9, 17, 45, 14889, zone)
        self.assertEqual(dt - ext_dt, timedelta(days=util.extended_datetime.DAYS_IN_400_YEARS))
        self.assertEqual(ext_dt - dt, -timedelta(days=util.extended_datetime.DAYS_IN_400_YEARS))

        with self.assertRaises(TypeError):
            ext_dt - "test"

    def test_extended_datetime_compare_tzinfo(self):
        with self.assertRaises(TypeError):
            self.assertTrue(util.extended_datetime(0, 1, 1, tzinfo=utc) < datetime(1, 1, 1))
        with self.assertRaises(TypeError):
            self.assertTrue(util.extended_datetime(0, 1, 1) < datetime(1, 1, 1, tzinfo=utc))

    def test_extended_datetime_date_time(self):
        self.assertEqual(util.extended_date(0, 1, 1), util.extended_datetime(0, 1, 1).date())
        self.assertEqual(util.extended_date(0, 2, 29), util.extended_datetime(0, 2, 29).date())
        self.assertEqual(time(0, 0, 0), util.extended_datetime(0, 1, 1).time())

    def test_iri_to_uri(self):
        self.assertEqual(
            b'ldap://ldap.e-szigno.hu/CN=Microsec%20e-Szigno%20Root%20CA,OU=e-Szigno%20CA,'
            b'O=Microsec%20Ltd.,L=Budapest,C=HU?certificateRevocationList;binary',
            util.iri_to_uri(
                'ldap://ldap.e-szigno.hu/CN=Microsec e-Szigno Root CA,'
                'OU=e-Szigno CA,O=Microsec Ltd.,L=Budapest,C=HU?certificateRevocationList;binary'
            )
        )
        self.assertEqual(
            b'ldap://directory.d-trust.net/CN=D-TRUST%20Root%20Class%203%20CA%202%202009,'
            b'O=D-Trust%20GmbH,C=DE?certificaterevocationlist',
            util.iri_to_uri(
                'ldap://directory.d-trust.net/CN=D-TRUST Root Class 3 CA 2 2009,'
                'O=D-Trust GmbH,C=DE?certificaterevocationlist'
            )
        )
        self.assertEqual(
            b'ldap://directory.d-trust.net/CN=D-TRUST%20Root%20Class%203%20CA%202%20EV%202009,'
            b'O=D-Trust%20GmbH,C=DE?certificaterevocationlist',
            util.iri_to_uri(
                'ldap://directory.d-trust.net/CN=D-TRUST Root Class 3 CA 2 EV 2009,'
                'O=D-Trust GmbH,C=DE?certificaterevocationlist'
            )
        )
