# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
import sys

from asn1crypto import pkcs12
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class PKCS12Tests(unittest.TestCase):

    def test_parse_pfx(self):
        with open(os.path.join(fixtures_dir, 'test-tripledes.p12'), 'rb') as f:
            info = pkcs12.Pfx.load(f.read())

        self.assertEqual(
            'v3',
            info['version'].native
        )

        auth_safe = info['auth_safe']

        self.assertEqual(
            'data',
            auth_safe['content_type'].native
        )

        self.assertEqual(
            2,
            len(info.authenticated_safe)
        )

        for i, content_info in enumerate(info.authenticated_safe):
            if i == 0:
                self.assertEqual(
                    'encrypted_data',
                    content_info['content_type'].native
                )
            else:
                self.assertEqual(
                    'data',
                    content_info['content_type'].native
                )
                safe_contents = pkcs12.SafeContents.load(content_info['content'].native)
                self.assertEqual(
                    1,
                    len(safe_contents)
                )
                bag_attributes = safe_contents[0]['bag_attributes']
                self.assertEqual(
                    2,
                    len(bag_attributes)
                )
                self.assertEqual(
                    'local_key_id',
                    bag_attributes[0]['type'].native
                )
                self.assertEqual(
                    [b'\x95\xd7\xcf\xd7&\x80\x02\x94Q\xc2}X\xee\xd7\x9eiQ\xc0\x10P'],
                    bag_attributes[0]['values'].native
                )
                self.assertEqual(
                    'friendly_name',
                    bag_attributes[1]['type'].native
                )
                self.assertEqual(
                    ['PKCS#12 Test'],
                    bag_attributes[1]['values'].native
                )

    def test_parse_certbag(self):
        '''test to parse the java oid "2.16.840.1.113894.746875.1.1"'''
        with open(os.path.join(fixtures_dir, 'certbag.der'), 'rb') as f:
            certbag = pkcs12.SafeBag.load(f.read())

        self.assertEqual(
            2,
            len(certbag['bag_attributes'])
        )

        attr_0 = certbag['bag_attributes'][0]

        self.assertEqual(
            'friendly_name',
            attr_0['type'].native
        )

        self.assertEqual(
            ['testcertificate'],
            attr_0['values'].native
        )

        attr_1 = certbag['bag_attributes'][1]

        self.assertEqual(
            'trusted_key_usage',
            attr_1['type'].native
        )

        self.assertEqual(
            ['any_extended_key_usage'],
            attr_1['values'].native
        )
