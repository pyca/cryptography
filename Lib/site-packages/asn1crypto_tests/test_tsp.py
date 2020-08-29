# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
from datetime import datetime

from asn1crypto import tsp, cms, util
from ._unittest_compat import patch

patch()

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class TSPTests(unittest.TestCase):

    def test_parse_request(self):
        with open(os.path.join(fixtures_dir, 'tsp_request'), 'rb') as f:
            request = tsp.TimeStampReq.load(f.read())

        self.assertEqual(
            'v1',
            request['version'].native
        )
        self.assertEqual(
            'sha1',
            request['message_imprint']['hash_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            request['message_imprint']['hash_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB',
            request['message_imprint']['hashed_message'].native
        )
        self.assertEqual(
            17842879675353045770,
            request['nonce'].native
        )

    def test_parse_response(self):
        with open(os.path.join(fixtures_dir, 'tsp_response'), 'rb') as f:
            response = tsp.TimeStampResp.load(f.read())

        status_info = response['status']
        token = response['time_stamp_token']
        signed_data = token['content']
        encap_content_info = signed_data['encap_content_info']
        tst_info = encap_content_info['content'].parsed
        signer_infos = signed_data['signer_infos']
        signer_info = signer_infos[0]
        signed_attrs = signer_info['signed_attrs']

        self.assertEqual(
            'granted',
            status_info['status'].native
        )
        self.assertEqual(
            None,
            status_info['status_string'].native
        )
        self.assertEqual(
            None,
            status_info['fail_info'].native
        )
        self.assertEqual(
            'signed_data',
            token['content_type'].native
        )
        self.assertIsInstance(
            signed_data,
            cms.SignedData
        )
        self.assertEqual(
            'v3',
            signed_data['version'].native
        )
        self.assertEqual(
            'sha1',
            signed_data['digest_algorithms'][0]['algorithm'].native
        )
        self.assertEqual(
            'tst_info',
            encap_content_info['content_type'].native
        )
        self.assertIsInstance(
            tst_info,
            tsp.TSTInfo
        )
        self.assertEqual(
            'v1',
            tst_info['version'].native
        )
        self.assertEqual(
            '1.1.2',
            tst_info['policy'].native
        )
        self.assertEqual(
            'sha1',
            tst_info['message_imprint']['hash_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            tst_info['message_imprint']['hash_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB',
            tst_info['message_imprint']['hashed_message'].native
        )
        self.assertEqual(
            544918635,
            tst_info['serial_number'].native
        )
        self.assertEqual(
            datetime(2015, 6, 1, 18, 39, 55, tzinfo=util.timezone.utc),
            tst_info['gen_time'].native
        )
        self.assertEqual(
            60,
            tst_info['accuracy']['seconds'].native
        )
        self.assertEqual(
            None,
            tst_info['accuracy']['millis'].native
        )
        self.assertEqual(
            None,
            tst_info['accuracy']['micros'].native
        )
        self.assertEqual(
            False,
            tst_info['ordering'].native
        )
        self.assertEqual(
            17842879675353045770,
            tst_info['nonce'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('organization_name', 'GeoTrust Inc'),
                ('common_name', 'GeoTrust Timestamping Signer 1'),
            ]),
            tst_info['tsa'].native
        )
        self.assertEqual(
            None,
            tst_info['extensions'].native
        )
        self.assertEqual(
            None,
            signed_data['certificates'].native
        )
        self.assertEqual(
            None,
            signed_data['crls'].native
        )
        self.assertEqual(
            1,
            len(signer_infos)
        )
        self.assertEqual(
            'v1',
            signer_info['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'ZA'),
                        ('state_or_province_name', 'Western Cape'),
                        ('locality_name', 'Durbanville'),
                        ('organization_name', 'Thawte'),
                        ('organizational_unit_name', 'Thawte Certification'),
                        ('common_name', 'Thawte Timestamping CA'),
                    ])
                ),
                (
                    'serial_number',
                    125680471847352264461591953321128732863
                )
            ]),
            signer_info['sid'].native
        )
        self.assertEqual(
            'sha1',
            signer_info['digest_algorithm']['algorithm'].native
        )
        self.assertEqual(
            4,
            len(signed_attrs)
        )
        self.assertEqual(
            'content_type',
            signed_attrs[0]['type'].native
        )
        self.assertEqual(
            'tst_info',
            signed_attrs[0]['values'][0].native
        )
        self.assertEqual(
            'signing_time',
            signed_attrs[1]['type'].native
        )
        self.assertEqual(
            datetime(2015, 6, 1, 18, 39, 55, tzinfo=util.timezone.utc),
            signed_attrs[1]['values'][0].native
        )
        self.assertEqual(
            'message_digest',
            signed_attrs[2]['type'].native
        )
        self.assertEqual(
            b'\x22\x06\x7D\xA4\xFC\x7B\xC5\x94\x80\xB4\xB0\x78\xC2\x07\x66\x02\xA3\x0D\x62\xAE',
            signed_attrs[2]['values'][0].native
        )
        self.assertEqual(
            'signing_certificate',
            signed_attrs[3]['type'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'certs',
                    [
                        util.OrderedDict([
                            (
                                'cert_hash',
                                b'\x22\x3C\xDA\x27\x07\x96\x73\x81\x6B\x60\x8A\x1B\x8C\xB0\xAB\x02\x30\x10\x7F\xCC'
                            ),
                            ('issuer_serial', None),
                        ])
                    ]
                ),
                (
                    'policies',
                    None
                )
            ]),
            signed_attrs[3]['values'][0].native
        )
