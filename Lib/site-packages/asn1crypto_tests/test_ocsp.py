# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os
from datetime import datetime

from asn1crypto import ocsp, util
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class OCSPTests(unittest.TestCase):

    def test_parse_request(self):
        with open(os.path.join(fixtures_dir, 'ocsp_request'), 'rb') as f:
            request = ocsp.OCSPRequest.load(f.read())

        tbs_request = request['tbs_request']
        request_list = tbs_request['request_list']
        single_request = request_list[0]
        req_cert = single_request['req_cert']

        self.assertEqual(
            'v1',
            tbs_request['version'].native
        )
        self.assertEqual(
            None,
            tbs_request['requestor_name'].native
        )
        self.assertEqual(
            'sha1',
            req_cert['hash_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            req_cert['hash_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\xAA\x2B\x03\x14\xAF\x64\x2E\x13\x0E\xD6\x92\x25\xE3\xFF\x2A\xBA\xD7\x3D\x62\x30',
            req_cert['issuer_name_hash'].native
        )
        self.assertEqual(
            b'\xDE\xCF\x5C\x50\xB7\xAE\x02\x1F\x15\x17\xAA\x16\xE8\x0D\xB5\x28\x9D\x6A\x5A\xF3',
            req_cert['issuer_key_hash'].native
        )
        self.assertEqual(
            130338219198307073574879940486642352162,
            req_cert['serial_number'].native
        )

    def test_parse_response(self):
        with open(os.path.join(fixtures_dir, 'ocsp_response'), 'rb') as f:
            response = ocsp.OCSPResponse.load(f.read())

        response_bytes = response['response_bytes']
        basic_ocsp_response = response_bytes['response'].parsed
        tbs_response_data = basic_ocsp_response['tbs_response_data']
        responder_id = tbs_response_data['responder_id']
        single_response = tbs_response_data['responses'][0]
        cert_id = single_response['cert_id']
        cert = basic_ocsp_response['certs'][0]

        self.assertEqual(
            'successful',
            response['response_status'].native
        )
        self.assertEqual(
            'basic_ocsp_response',
            response_bytes['response_type'].native
        )
        self.assertEqual(
            'sha1_rsa',
            basic_ocsp_response['signature_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            basic_ocsp_response['signature_algorithm']['parameters'].native
        )
        self.assertEqual(
            'v1',
            tbs_response_data['version'].native
        )
        self.assertEqual(
            b'\x4E\xC5\x63\xD6\xB2\x05\x05\xD7\x76\xF0\x07\xED\xAC\x7D\x5A\x56\x97\x7B\xBD\x3C',
            responder_id.native
        )
        self.assertEqual(
            'by_key',
            responder_id.name
        )
        self.assertEqual(
            datetime(2015, 5, 22, 16, 24, 8, tzinfo=util.timezone.utc),
            tbs_response_data['produced_at'].native
        )
        self.assertEqual(
            'sha1',
            cert_id['hash_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            cert_id['hash_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\xAA\x2B\x03\x14\xAF\x64\x2E\x13\x0E\xD6\x92\x25\xE3\xFF\x2A\xBA\xD7\x3D\x62\x30',
            cert_id['issuer_name_hash'].native
        )
        self.assertEqual(
            b'\xDE\xCF\x5C\x50\xB7\xAE\x02\x1F\x15\x17\xAA\x16\xE8\x0D\xB5\x28\x9D\x6A\x5A\xF3',
            cert_id['issuer_key_hash'].native
        )
        self.assertEqual(
            130338219198307073574879940486642352162,
            cert_id['serial_number'].native
        )
        self.assertEqual(
            datetime(2015, 5, 22, 16, 24, 8, tzinfo=util.timezone.utc),
            single_response['this_update'].native
        )
        self.assertEqual(
            datetime(2015, 5, 29, 16, 24, 8, tzinfo=util.timezone.utc),
            single_response['next_update'].native
        )
        self.assertEqual(
            None,
            single_response['single_extensions'].native
        )
        self.assertEqual(
            None,
            tbs_response_data['response_extensions'].native
        )
        self.assertIsInstance(
            basic_ocsp_response['certs'].native,
            list
        )
        self.assertEqual(
            1,
            len(basic_ocsp_response['certs'])
        )
        self.assertEqual(
            'v3',
            cert['tbs_certificate']['version'].native
        )

    def test_cert_status_native(self):
        status = ocsp.CertStatus.load(b'\x80\x00')
        self.assertEqual('good', status.native)

        status = ocsp.CertStatus(('good', ocsp.StatusGood()))
        self.assertEqual('good', status.native)

        with self.assertRaises(ValueError):
            ocsp.StatusGood('unknown')

        status = ocsp.CertStatus.load(
            b'\xa1\x16\x18\x0f\x32\x30\x31\x38\x31\x30\x30\x33'
            b'\x31\x34\x35\x33\x34\x37\x5a\xa0\x03\x0a\x01\x01'
        )
        self.assertIsInstance(
            status.native,
            util.OrderedDict
        )

        status = ocsp.CertStatus.load(b'\x82\x00')
        self.assertEqual('unknown', status.native)

        status = ocsp.CertStatus(('unknown', ocsp.StatusUnknown()))
        self.assertEqual('unknown', status.native)

        with self.assertRaises(ValueError):
            ocsp.StatusUnknown('good')
