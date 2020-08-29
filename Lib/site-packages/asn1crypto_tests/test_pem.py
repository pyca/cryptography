# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from asn1crypto import pem, util

from .unittest_data import data_decorator, data
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
    num_cls = long  # noqa
else:
    byte_cls = bytes
    num_cls = int


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


@data_decorator
class PEMTests(unittest.TestCase):

    @staticmethod
    def detect_files():
        return (
            (
                'keys/test-der.crt',
                False
            ),
            (
                'keys/test-inter-der.crt',
                False
            ),
            (
                'keys/test-third-der.crt',
                False
            ),
            (
                'keys/test.crt',
                True
            ),
            (
                'keys/test-inter.crt',
                True
            ),
            (
                'keys/test-third.crt',
                True
            ),
        )

    @data('detect_files')
    def detect(self, relative_path, is_pem):
        with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
            byte_string = f.read()
        self.assertEqual(is_pem, pem.detect(byte_string))

    @staticmethod
    def unarmor_armor_files():
        return (
            (
                'keys/test.crt',
                'keys/test-der.crt',
                'CERTIFICATE',
                {}
            ),
            (
                'keys/test-inter.crt',
                'keys/test-inter-der.crt',
                'CERTIFICATE',
                {}
            ),
            (
                'keys/test-third.crt',
                'keys/test-third-der.crt',
                'CERTIFICATE',
                {}
            ),
            (
                'keys/test-pkcs8.key',
                'keys/test-pkcs8-der.key',
                'PRIVATE KEY',
                {}
            ),
            (
                'test-third.csr',
                'test-third-der.csr',
                'CERTIFICATE REQUEST',
                {}
            ),
            (
                'keys/test-aes128.key',
                'keys/test-aes128-der.key',
                'RSA PRIVATE KEY',
                util.OrderedDict([
                    ('Proc-Type', '4,ENCRYPTED'),
                    ('DEK-Info', 'AES-128-CBC,01F6EE04516C912788B11BD7377626C2')
                ])
            ),
        )

    @data('unarmor_armor_files')
    def unarmor(self, relative_path, expected_bytes_filename, expected_type_name, expected_headers):
        with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
            byte_string = f.read()

        type_name, headers, decoded_bytes = pem.unarmor(byte_string)
        self.assertEqual(expected_type_name, type_name)
        self.assertEqual(expected_headers, headers)
        with open(os.path.join(fixtures_dir, expected_bytes_filename), 'rb') as f:
            expected_bytes = f.read()
            self.assertEqual(expected_bytes, decoded_bytes)

    def test_unarmor_multiple(self):
        data = self.unarmor_armor_files()
        input_data = b''
        der_data = []
        for pem_file, der_file in ((data[0][0], data[0][1]), (data[1][0], data[1][1])):
            with open(os.path.join(fixtures_dir, pem_file), 'rb') as f:
                input_data += f.read() + b'\n'
            with open(os.path.join(fixtures_dir, der_file), 'rb') as f:
                der_data.append(f.read())
        i = 0
        for name, headers, der_bytes in pem.unarmor(input_data, True):
            self.assertEqual('CERTIFICATE', name)
            self.assertEqual({}, headers)
            self.assertEqual(der_data[i], der_bytes)
            i += 1
        self.assertEqual(2, i)

    @data('unarmor_armor_files')
    def armor(self, expected_bytes_filename, relative_path, type_name, headers):
        with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
            byte_string = f.read()

        encoded_bytes = pem.armor(type_name, byte_string, headers=headers)
        with open(os.path.join(fixtures_dir, expected_bytes_filename), 'rb') as f:
            expected_bytes = f.read()
            # In case a user on Windows has CRLF translation on in Git.
            # Ran into this with the GitHub Actions Windows environments.
            expected_bytes = expected_bytes.replace(b'\r\n', b'\n')
            self.assertEqual(expected_bytes, encoded_bytes)

    def test_armor_wrong_type(self):
        with self.assertRaisesRegex(TypeError, 'type_name must be a unicode string'):
            pem.armor(b'CERTIFICATE', b'')

    def test_armor_wrong_type2(self):
        with self.assertRaisesRegex(TypeError, 'der_bytes must be a byte string'):
            pem.armor('CERTIFICATE', '')

    def test_detect_wrong_type(self):
        with self.assertRaisesRegex(TypeError, 'byte_string must be a byte string'):
            pem.detect('CERTIFICATE')
