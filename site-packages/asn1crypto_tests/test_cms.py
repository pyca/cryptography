# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
import zlib
import sys
from datetime import datetime

from asn1crypto import cms, util
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CMSTests(unittest.TestCase):

    def test_create_content_info_data(self):
        data = cms.SignedData({
            'version': 'v1',
            'encap_content_info': {
                'content_type': 'data',
                'content': b'Hello',
            }
        })
        info = data['encap_content_info']

        self.assertEqual('v1', data['version'].native)
        self.assertEqual(
            'data',
            info['content_type'].native
        )
        self.assertEqual(
            b'Hello',
            info['content'].native
        )
        self.assertIsInstance(info, cms.ContentInfo)

    def test_create_content_info_data_v2(self):
        data = cms.SignedData({
            'version': 'v2',
            'encap_content_info': {
                'content_type': 'data',
                'content': b'Hello',
            }
        })
        info = data['encap_content_info']

        self.assertEqual('v2', data['version'].native)
        self.assertEqual(
            'data',
            info['content_type'].native
        )
        self.assertEqual(
            b'Hello',
            info['content'].native
        )
        self.assertIsInstance(info, cms.EncapsulatedContentInfo)

    def test_parse_content_info_data(self):
        with open(os.path.join(fixtures_dir, 'message.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        self.assertEqual(
            'data',
            info['content_type'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\r\n',
            info['content'].native
        )

    def test_parse_content_info_compressed_data(self):
        with open(os.path.join(fixtures_dir, 'cms-compressed.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        compressed_data = info['content']

        self.assertEqual(
            'compressed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            compressed_data['version'].native
        )
        self.assertEqual(
            'zlib',
            compressed_data['compression_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            compressed_data['compression_algorithm']['parameters'].native
        )
        self.assertEqual(
            'data',
            compressed_data['encap_content_info']['content_type'].native
        )
        self.assertEqual(
            b'\x78\x9C\x0B\xC9\xC8\x2C\x56\x00\xA2\x92\x8C\x54\x85\xDC\xD4\xE2\xE2\xC4\xF4\x54\x85\x92\x7C\x85\xD4\xBC'
            b'\xE4\xC4\x82\xE2\xD2\x9C\xC4\x92\x54\x85\xCC\x3C\x85\x00\x6F\xE7\x60\x65\x73\x7D\x67\xDF\x60\x2E\x00\xB5'
            b'\xCF\x10\x71',
            compressed_data['encap_content_info']['content'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\n',
            compressed_data.decompressed
        )

    def test_parse_content_info_indefinite(self):
        with open(os.path.join(fixtures_dir, 'meca2_compressed.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        compressed_data = info['content']

        self.assertEqual(
            'compressed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            compressed_data['version'].native
        )
        self.assertEqual(
            'zlib',
            compressed_data['compression_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            compressed_data['compression_algorithm']['parameters'].native
        )
        self.assertEqual(
            'data',
            compressed_data['encap_content_info']['content_type'].native
        )
        data = compressed_data['encap_content_info']['content'].native
        self.assertIsInstance(zlib.decompress(data), byte_cls)

    def test_parse_content_info_digested_data(self):
        with open(os.path.join(fixtures_dir, 'cms-digested.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        digested_data = info['content']

        self.assertEqual(
            'digested_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            digested_data['version'].native
        )
        self.assertEqual(
            'sha1',
            digested_data['digest_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            digested_data['digest_algorithm']['parameters'].native
        )
        self.assertEqual(
            'data',
            digested_data['encap_content_info']['content_type'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\n',
            digested_data['encap_content_info']['content'].native
        )
        self.assertEqual(
            b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB',
            digested_data['digest'].native
        )

    def test_parse_content_info_encrypted_data(self):
        with open(os.path.join(fixtures_dir, 'cms-encrypted.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        encrypted_data = info['content']
        encrypted_content_info = encrypted_data['encrypted_content_info']

        self.assertEqual(
            'encrypted_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            encrypted_data['version'].native
        )
        self.assertEqual(
            'data',
            encrypted_content_info['content_type'].native
        )
        self.assertEqual(
            'aes128_cbc',
            encrypted_content_info['content_encryption_algorithm']['algorithm'].native
        )
        self.assertEqual(
            'aes',
            encrypted_content_info['content_encryption_algorithm'].encryption_cipher
        )
        self.assertEqual(
            'cbc',
            encrypted_content_info['content_encryption_algorithm'].encryption_mode
        )
        self.assertEqual(
            16,
            encrypted_content_info['content_encryption_algorithm'].key_length
        )
        self.assertEqual(
            16,
            encrypted_content_info['content_encryption_algorithm'].encryption_block_size
        )
        self.assertEqual(
            b'\x1F\x34\x54\x9F\x7F\xB7\x06\xBD\x81\x57\x68\x84\x79\xB5\x2F\x6F',
            encrypted_content_info['content_encryption_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\x80\xEE\x34\x8B\xFC\x04\x69\x4F\xBE\x15\x1C\x0C\x39\x2E\xF3\xEA\x8E\xEE\x17\x0D\x39\xC7\x4B\x6C\x4B'
            b'\x13\xEF\x17\x82\x0D\xED\xBA\x6D\x2F\x3B\xAB\x4E\xEB\xF0\xDB\xD9\x6E\x1C\xC2\x3C\x1C\x4C\xFA\xF3\x98'
            b'\x9B\x89\xBD\x48\x77\x07\xE2\x6B\x71\xCF\xB7\xFF\xCE\xA5',
            encrypted_content_info['encrypted_content'].native
        )

    def test_parse_content_info_enveloped_data(self):
        with open(os.path.join(fixtures_dir, 'cms-enveloped.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        enveloped_data = info['content']
        encrypted_content_info = enveloped_data['encrypted_content_info']
        recipient = enveloped_data['recipient_infos'][0].chosen

        self.assertEqual(
            'enveloped_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v0',
            enveloped_data['version'].native
        )
        self.assertEqual(
            None,
            enveloped_data['originator_info'].native
        )
        self.assertEqual(
            1,
            len(enveloped_data['recipient_infos'])
        )
        self.assertEqual(
            'v0',
            recipient['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            recipient['rid'].native
        )
        self.assertEqual(
            'rsaes_pkcs1v15',
            recipient['key_encryption_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            recipient['key_encryption_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\x97\x0A\xFD\x3B\x5C\x27\x45\x69\xCC\xDD\x45\x9E\xA7\x3C\x07\x27\x35\x16\x20\x21\xE4\x6E\x1D\xF8'
            b'\x5B\xE8\x7F\xD8\x40\x41\xE9\xF2\x92\xCD\xC8\xC5\x03\x95\xEC\x6C\x0B\x97\x71\x87\x86\x3C\xEB\x68'
            b'\x84\x06\x4E\xE6\xD0\xC4\x7D\x32\xFE\xA6\x06\xC9\xD5\xE1\x8B\xDA\xBF\x96\x5C\x20\x15\x49\x64\x7A'
            b'\xA2\x4C\xFF\x8B\x0D\xEA\x76\x35\x9B\x7C\x43\xF7\x21\x95\x26\xE7\x70\x30\x98\x5F\x0D\x5E\x4A\xCB'
            b'\xAD\x47\xDF\x46\xDA\x1F\x0E\xE2\xFE\x3A\x40\xD9\xF2\xDC\x0C\x97\xD9\x91\xED\x34\x8D\xF3\x73\xB0'
            b'\x90\xF9\xDD\x31\x4D\x37\x93\x81\xD3\x92\xCB\x72\x4A\xD6\x9D\x01\x82\x85\xD5\x1F\xE2\xAA\x32\x12'
            b'\x82\x4E\x17\xF6\xAA\x58\xDE\xBD\x1B\x80\xAF\x61\xF1\x8A\xD1\x7F\x9D\x41\x6A\xC0\xE4\xC7\x7E\x17'
            b'\xDC\x94\x33\xE9\x74\x7E\xE9\xF8\x5C\x30\x87\x9B\xD6\xF0\xE3\x4A\xB7\xE3\xCC\x51\x8A\xD4\x37\xF1'
            b'\xF9\x33\xB5\xD6\x1F\x36\xC1\x6F\x91\xA8\x5F\xE2\x6B\x08\xC7\x9D\xE8\xFD\xDC\xE8\x78\xE0\xC0\xC7'
            b'\xCF\xC5\xEE\x60\xEC\x54\xFF\x1A\x9C\xF7\x4E\x2C\xD0\x88\xDC\xC2\x1F\xDC\x8A\x37\x9B\x71\x20\xFF'
            b'\xFD\x6C\xE5\xBA\x8C\xDF\x0E\x3F\x20\xC6\xCB\x08\xA7\x07\xDB\x83',
            recipient['encrypted_key'].native
        )
        self.assertEqual(
            'data',
            encrypted_content_info['content_type'].native
        )
        self.assertEqual(
            'tripledes_3key',
            encrypted_content_info['content_encryption_algorithm']['algorithm'].native
        )
        self.assertEqual(
            'tripledes',
            encrypted_content_info['content_encryption_algorithm'].encryption_cipher
        )
        self.assertEqual(
            'cbc',
            encrypted_content_info['content_encryption_algorithm'].encryption_mode
        )
        self.assertEqual(
            24,
            encrypted_content_info['content_encryption_algorithm'].key_length
        )
        self.assertEqual(
            8,
            encrypted_content_info['content_encryption_algorithm'].encryption_block_size
        )
        self.assertEqual(
            b'\x52\x50\x98\xFA\x33\x88\xC7\x3C',
            encrypted_content_info['content_encryption_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\xDC\x88\x55\x08\xE5\x67\x70\x49\x99\x54\xFD\xF8\x40\x7C\x38\xD5\x78\x1D\x6A\x95\x6D\x1E\xC4\x12'
            b'\x39\xFE\xC0\x76\xDC\xF5\x79\x1A\x69\xA1\xB9\x40\x1E\xCF\xC8\x79\x3E\xF3\x38\xB4\x90\x00\x27\xD1'
            b'\xB5\x64\xAB\x99\x51\x13\xF1\x0A',
            encrypted_content_info['encrypted_content'].native
        )
        self.assertEqual(
            None,
            enveloped_data['unprotected_attrs'].native
        )

    def test_parse_content_info_cms_signed_data(self):
        with open(os.path.join(fixtures_dir, 'cms-signed.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        signed_data = info['content']
        encap_content_info = signed_data['encap_content_info']

        self.assertEqual(
            'signed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v1',
            signed_data['version'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('algorithm', 'sha256'),
                    ('parameters', None),
                ])
            ],
            signed_data['digest_algorithms'].native
        )
        self.assertEqual(
            'data',
            encap_content_info['content_type'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\r\n',
            encap_content_info['content'].native
        )

        self.assertEqual(
            1,
            len(signed_data['certificates'])
        )
        certificate = signed_data['certificates'][0]
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            self.assertEqual(
                f.read(),
                certificate.dump()
            )

        self.assertEqual(
            1,
            len(signed_data['signer_infos'])
        )
        signer = signed_data['signer_infos'][0]

        self.assertEqual(
            'v1',
            signer['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            signer['sid'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'sha256'),
                ('parameters', None),
            ]),
            signer['digest_algorithm'].native
        )

        signed_attrs = signer['signed_attrs']

        self.assertEqual(
            3,
            len(signed_attrs)
        )
        self.assertEqual(
            'content_type',
            signed_attrs[0]['type'].native
        )
        self.assertEqual(
            'data',
            signed_attrs[0]['values'][0].native
        )
        self.assertEqual(
            'signing_time',
            signed_attrs[1]['type'].native
        )
        self.assertEqual(
            datetime(2015, 5, 30, 13, 12, 38, tzinfo=util.timezone.utc),
            signed_attrs[1]['values'][0].native
        )
        self.assertEqual(
            'message_digest',
            signed_attrs[2]['type'].native
        )
        self.assertEqual(
            b'\xA1\x30\xE2\x87\x90\x5A\x58\x15\x7A\x44\x54\x7A\xB9\xBC\xAE\xD3\x00\xF3\xEC\x3E\x97\xFF'
            b'\x03\x20\x79\x34\x9D\x62\xAA\x20\xA5\x1D',
            signed_attrs[2]['values'][0].native
        )

        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsassa_pkcs1v15'),
                ('parameters', None),
            ]),
            signer['signature_algorithm'].native
        )
        self.assertEqual(
            b'\xAC\x2F\xE3\x25\x39\x8F\xD3\xDF\x80\x4F\x0D\xBA\xB1\xEE\x99\x09\xA9\x21\xBB\xDF\x3C\x1E'
            b'\x70\xDA\xDF\xC4\x0F\x1D\x10\x29\xBC\x94\xBE\xF8\xA8\xC2\x2D\x2A\x1F\x14\xBC\x4A\x5B\x66'
            b'\x7F\x6F\xE4\xDF\x82\x4D\xD9\x3F\xEB\x89\xAA\x05\x1A\xE5\x58\xCE\xC4\x33\x53\x6E\xE4\x66'
            b'\xF9\x21\xCF\x80\x35\x46\x88\xB5\x6A\xEA\x5C\x54\x49\x40\x31\xD6\xDC\x20\xD8\xA0\x63\x8C'
            b'\xC1\xC3\xA1\x72\x5D\x0D\xCE\x43\xB1\x5C\xD8\x32\x3F\xA9\xE7\xBB\xD9\x56\xAE\xE7\xFB\x7C'
            b'\x37\x32\x8B\x93\xC2\xC4\x47\xDD\x00\xFB\x1C\xEF\xC3\x68\x32\xDC\x06\x26\x17\x45\xF5\xB3'
            b'\xDC\xD8\x5C\x2B\xC1\x8B\x97\x93\xB8\xF1\x85\xE2\x92\x3B\xC4\x6A\x6A\x89\xC5\x14\x51\x4A'
            b'\x06\x11\x54\xB0\x29\x07\x75\xD8\xDF\x6B\xFB\x21\xE4\xA4\x09\x17\xAF\xAC\xA0\xF5\xC0\xFE'
            b'\x7B\x03\x04\x40\x41\x57\xC4\xFD\x58\x1D\x10\x5E\xAC\x23\xAB\xAA\x80\x95\x96\x02\x71\x84'
            b'\x9C\x0A\xBD\x54\xC4\xA2\x47\xAA\xE7\xC3\x09\x13\x6E\x26\x7D\x72\xAA\xA9\x0B\xF3\xCC\xC4'
            b'\x48\xB4\x97\x14\x00\x47\x2A\x6B\xD3\x93\x3F\xD8\xFD\xAA\xB9\xFB\xFB\xD5\x09\x8D\x82\x8B'
            b'\xDE\x0F\xED\x39\x6D\x7B\xDC\x76\x8B\xA6\x4E\x9B\x7A\xBA',
            signer['signature'].native
        )

    def test_parse_content_info_pkcs7_signed_data(self):
        with open(os.path.join(fixtures_dir, 'pkcs7-signed.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        signed_data = info['content']
        encap_content_info = signed_data['encap_content_info']

        self.assertEqual(
            'signed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v1',
            signed_data['version'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('algorithm', 'sha256'),
                    ('parameters', None),
                ])
            ],
            signed_data['digest_algorithms'].native
        )
        self.assertEqual(
            'data',
            encap_content_info['content_type'].native
        )
        self.assertEqual(
            b'This is the message to encapsulate in PKCS#7/CMS\n',
            encap_content_info['content'].native
        )

        self.assertEqual(
            1,
            len(signed_data['certificates'])
        )
        certificate = signed_data['certificates'][0]
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            self.assertEqual(
                f.read(),
                certificate.dump()
            )

        self.assertEqual(
            1,
            len(signed_data['signer_infos'])
        )
        signer = signed_data['signer_infos'][0]

        self.assertEqual(
            'v1',
            signer['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            signer['sid'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'sha256'),
                ('parameters', None),
            ]),
            signer['digest_algorithm'].native
        )

        signed_attrs = signer['signed_attrs']

        self.assertEqual(
            4,
            len(signed_attrs)
        )
        self.assertEqual(
            'content_type',
            signed_attrs[0]['type'].native
        )
        self.assertEqual(
            'data',
            signed_attrs[0]['values'][0].native
        )
        self.assertEqual(
            'signing_time',
            signed_attrs[1]['type'].native
        )
        self.assertEqual(
            datetime(2015, 6, 3, 5, 55, 12, tzinfo=util.timezone.utc),
            signed_attrs[1]['values'][0].native
        )
        self.assertEqual(
            'message_digest',
            signed_attrs[2]['type'].native
        )
        self.assertEqual(
            b'\x52\x88\x25\x47\x15\x5B\x2D\x50\x44\x68\x05\x24\xC8\x71\x5A\xCC\x62\x28\x36\x17\xB7\x68'
            b'\xEE\xA1\x12\x90\x96\x4F\x94\xAE\xDB\x79',
            signed_attrs[2]['values'][0].native
        )

        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsassa_pkcs1v15'),
                ('parameters', None),
            ]),
            signer['signature_algorithm'].native
        )
        self.assertEqual(
            b'\x43\x66\xEE\xF4\x6A\x02\x6F\xFE\x0D\xAE\xE6\xF3\x7A\x8F\x2C\x8E\x26\xB6\x25\x68\xEF\x5B'
            b'\x4B\x4F\x9C\xE4\xE6\x71\x42\x22\xEC\x97\xFC\x53\xD9\xD6\x36\x1F\xA1\x32\x35\xFF\xA9\x95'
            b'\x45\x50\x36\x36\x0C\x9A\x10\x6F\x06\xB6\x9D\x25\x10\x08\xF5\xF4\xE1\x68\x62\x60\xE5\xBF'
            b'\xBD\xE2\x9F\xBD\x8A\x10\x29\x3B\xAF\xE7\xD6\x55\x7C\xEE\x3B\xFB\x93\x42\xE0\xB4\x4F\x89'
            b'\xD0\x7B\x18\x51\x85\x90\x47\xF0\x5E\xE1\x15\x2C\xC1\x9A\xF1\x49\xE8\x11\x29\x17\x2E\x77'
            b'\xD3\x35\x10\xAA\xCD\x32\x07\x32\x74\xCF\x2D\x89\xBD\xEF\xC7\xC9\xE7\xEC\x90\x44\xCE\x0B'
            b'\xC5\x97\x00\x26\x67\x8A\x89\x5B\xFA\x46\xB2\x92\xD5\xCB\xA3\x52\x16\xDC\xF0\xF0\x79\xCB'
            b'\x90\x93\x8E\x26\xB3\xEB\x8F\xBD\x54\x06\xD6\xB0\xA0\x04\x47\x7C\x63\xFC\x88\x5A\xE3\x81'
            b'\xDF\x1E\x4D\x39\xFD\xF5\xA0\xE2\xD3\xAB\x13\xC1\xCF\x50\xB2\x0B\xC9\x36\xD6\xCB\xEA\x55'
            b'\x39\x97\x8E\x34\x47\xE3\x6B\x44\x4A\x0E\x03\xAF\x41\xB2\x47\x2E\x26\xA3\x6B\x5F\xA1\x5C'
            b'\x86\xA1\x96\x37\x02\xD3\x7C\x5F\xC1\xAF\x81\xE4\x1A\xD9\x87\x44\xB5\xB3\x5C\x45\x6C\xFF'
            b'\x97\x4C\x3A\xB4\x2F\x5C\x2F\x86\x15\x51\x71\xA6\x27\x68',
            signer['signature'].native
        )

    def test_parse_cms_signed_date_indefinite_length(self):
        with open(os.path.join(fixtures_dir, 'cms-signed-indefinite-length.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())
            signed_data = info['content']
            self.assertIsInstance(signed_data.native, util.OrderedDict)

    def test_parse_content_info_cms_signed_digested_data(self):
        with open(os.path.join(fixtures_dir, 'cms-signed-digested.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        signed_data = info['content']
        encap_content_info = signed_data['encap_content_info']

        self.assertEqual(
            'signed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v2',
            signed_data['version'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('algorithm', 'sha256'),
                    ('parameters', None),
                ])
            ],
            signed_data['digest_algorithms'].native
        )
        self.assertEqual(
            'digested_data',
            encap_content_info['content_type'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('version', 'v0'),
                (
                    'digest_algorithm',
                    util.OrderedDict([
                        ('algorithm', 'sha1'),
                        ('parameters', None),
                    ])
                ),
                (
                    'encap_content_info',
                    util.OrderedDict([
                        ('content_type', 'data'),
                        ('content', b'This is the message to encapsulate in PKCS#7/CMS\n'),
                    ])
                ),
                (
                    'digest',
                    b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB'
                )
            ]),
            encap_content_info['content'].native
        )

        self.assertEqual(
            1,
            len(signed_data['certificates'])
        )
        certificate = signed_data['certificates'][0]
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            self.assertEqual(
                f.read(),
                certificate.dump()
            )

        self.assertEqual(
            1,
            len(signed_data['signer_infos'])
        )
        signer = signed_data['signer_infos'][0]

        self.assertEqual(
            'v1',
            signer['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            signer['sid'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'sha256'),
                ('parameters', None),
            ]),
            signer['digest_algorithm'].native
        )

        signed_attrs = signer['signed_attrs']

        self.assertEqual(
            0,
            len(signed_attrs)
        )

        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsassa_pkcs1v15'),
                ('parameters', None),
            ]),
            signer['signature_algorithm'].native
        )
        self.assertEqual(
            b'\x70\xBC\x18\x82\x41\xD6\xD8\xE7\x5C\xDC\x42\x27\xA5\xA8\xAA\x8B\x16\x15\x61\x3A\xE5\x47'
            b'\x53\xFD\x8F\x45\xA3\x82\xE2\x72\x44\x07\xD1\xCB\xBF\xB4\x85\x4A\x2A\x16\x19\xDE\xDC\x53'
            b'\x15\xCF\x98\xEE\x5C\x0E\xDF\xDE\xC8\x79\xCE\x2B\x38\x61\x36\xB0\xA1\xCB\x94\xD6\x4F\xCD'
            b'\x83\xEF\x0C\xC9\x23\xA0\x7B\x8B\x65\x40\x5C\x3D\xA8\x3E\xCC\x0D\x1F\x17\x23\xF3\x74\x9F'
            b'\x7E\x88\xF8\xF3\xBE\x4E\x19\x95\x0F\xEB\x95\x55\x69\xB4\xAA\xC3\x2A\x36\x03\x93\x1C\xDC'
            b'\xE5\x65\x3F\x4E\x5E\x03\xC8\x56\xD8\x57\x8F\xE8\x2D\x85\x32\xDA\xFD\x79\xD4\xDD\x88\xCA'
            b'\xA3\x14\x41\xE4\x3B\x03\x88\x0E\x2B\x76\xDC\x44\x3D\x4D\xFF\xB2\xC8\xC3\x83\xB1\x33\x37'
            b'\x53\x51\x33\x4B\xCA\x1A\xAD\x7E\x6A\xBC\x61\x8B\x84\xDB\x7F\xCF\x61\xB2\x1D\x21\x83\xCF'
            b'\xB8\x3F\xC6\x98\xED\xD8\x66\x06\xCF\x03\x30\x96\x9D\xB4\x7A\x16\xDF\x6E\xA7\x30\xEB\x77'
            b'\xF7\x40\x13\xFB\xF2\xAC\x41\x79\x9D\xDC\xC0\xED\x4B\x8B\x19\xEE\x05\x3D\x61\x20\x39\x7E'
            b'\x80\x1D\x3A\x23\x69\x48\x43\x60\x8B\x3E\x63\xAD\x01\x7A\xDE\x6F\x01\xBA\x51\xF3\x4B\x14'
            b'\xBF\x6B\x77\x1A\x32\xC2\x0C\x93\xCC\x35\xBC\x66\xC6\x69',
            signer['signature'].native
        )

    def test_parse_content_info_pkcs7_signed_digested_data(self):
        with open(os.path.join(fixtures_dir, 'pkcs7-signed-digested.der'), 'rb') as f:
            info = cms.ContentInfo.load(f.read())

        signed_data = info['content']
        encap_content_info = signed_data['encap_content_info']

        self.assertEqual(
            'signed_data',
            info['content_type'].native
        )
        self.assertEqual(
            'v1',
            signed_data['version'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('algorithm', 'sha256'),
                    ('parameters', None),
                ])
            ],
            signed_data['digest_algorithms'].native
        )
        self.assertEqual(
            'digested_data',
            encap_content_info['content_type'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('version', 'v0'),
                (
                    'digest_algorithm',
                    util.OrderedDict([
                        ('algorithm', 'sha1'),
                        ('parameters', None),
                    ])
                ),
                (
                    'encap_content_info',
                    util.OrderedDict([
                        ('content_type', 'data'),
                        ('content', b'This is the message to encapsulate in PKCS#7/CMS\n'),
                    ])
                ),
                (
                    'digest',
                    b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB'
                )
            ]),
            encap_content_info['content'].native
        )

        self.assertEqual(
            1,
            len(signed_data['certificates'])
        )
        certificate = signed_data['certificates'][0]
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            self.assertEqual(
                f.read(),
                certificate.dump()
            )

        self.assertEqual(
            1,
            len(signed_data['signer_infos'])
        )
        signer = signed_data['signer_infos'][0]

        self.assertEqual(
            'v1',
            signer['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'US'),
                        ('state_or_province_name', 'Massachusetts'),
                        ('locality_name', 'Newbury'),
                        ('organization_name', 'Codex Non Sufficit LC'),
                        ('organizational_unit_name', 'Testing'),
                        ('common_name', 'Will Bond'),
                        ('email_address', 'will@codexns.io'),
                    ])
                ),
                (
                    'serial_number',
                    13683582341504654466
                )
            ]),
            signer['sid'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'sha256'),
                ('parameters', None),
            ]),
            signer['digest_algorithm'].native
        )

        signed_attrs = signer['signed_attrs']

        self.assertEqual(
            0,
            len(signed_attrs)
        )

        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsassa_pkcs1v15'),
                ('parameters', None),
            ]),
            signer['signature_algorithm'].native
        )
        self.assertEqual(
            b'\x70\xBC\x18\x82\x41\xD6\xD8\xE7\x5C\xDC\x42\x27\xA5\xA8\xAA\x8B\x16\x15\x61\x3A\xE5\x47'
            b'\x53\xFD\x8F\x45\xA3\x82\xE2\x72\x44\x07\xD1\xCB\xBF\xB4\x85\x4A\x2A\x16\x19\xDE\xDC\x53'
            b'\x15\xCF\x98\xEE\x5C\x0E\xDF\xDE\xC8\x79\xCE\x2B\x38\x61\x36\xB0\xA1\xCB\x94\xD6\x4F\xCD'
            b'\x83\xEF\x0C\xC9\x23\xA0\x7B\x8B\x65\x40\x5C\x3D\xA8\x3E\xCC\x0D\x1F\x17\x23\xF3\x74\x9F'
            b'\x7E\x88\xF8\xF3\xBE\x4E\x19\x95\x0F\xEB\x95\x55\x69\xB4\xAA\xC3\x2A\x36\x03\x93\x1C\xDC'
            b'\xE5\x65\x3F\x4E\x5E\x03\xC8\x56\xD8\x57\x8F\xE8\x2D\x85\x32\xDA\xFD\x79\xD4\xDD\x88\xCA'
            b'\xA3\x14\x41\xE4\x3B\x03\x88\x0E\x2B\x76\xDC\x44\x3D\x4D\xFF\xB2\xC8\xC3\x83\xB1\x33\x37'
            b'\x53\x51\x33\x4B\xCA\x1A\xAD\x7E\x6A\xBC\x61\x8B\x84\xDB\x7F\xCF\x61\xB2\x1D\x21\x83\xCF'
            b'\xB8\x3F\xC6\x98\xED\xD8\x66\x06\xCF\x03\x30\x96\x9D\xB4\x7A\x16\xDF\x6E\xA7\x30\xEB\x77'
            b'\xF7\x40\x13\xFB\xF2\xAC\x41\x79\x9D\xDC\xC0\xED\x4B\x8B\x19\xEE\x05\x3D\x61\x20\x39\x7E'
            b'\x80\x1D\x3A\x23\x69\x48\x43\x60\x8B\x3E\x63\xAD\x01\x7A\xDE\x6F\x01\xBA\x51\xF3\x4B\x14'
            b'\xBF\x6B\x77\x1A\x32\xC2\x0C\x93\xCC\x35\xBC\x66\xC6\x69',
            signer['signature'].native
        )

    def test_bad_teletex_inside_pkcs7(self):
        with open(os.path.join(fixtures_dir, 'mozilla-generated-by-openssl.pkcs7.der'), 'rb') as f:
            content = cms.ContentInfo.load(f.read())['content']
        self.assertEqual(
            util.OrderedDict([
                ('organizational_unit_name', 'Testing'),
                ('country_name', 'US'),
                ('locality_name', 'Mountain View'),
                ('organization_name', 'Addons Testing'),
                ('state_or_province_name', 'CA'),
                ('common_name', '{02b860db-e71f-48d2-a5a0-82072a93d33c}')
            ]),
            content['certificates'][0].chosen['tbs_certificate']['subject'].native
        )
