# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from asn1crypto import crl

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


class CRLTests(unittest.TestCase):

    def test_parse_crl(self):
        with open(os.path.join(fixtures_dir, 'eid2011.crl'), 'rb') as f:
            cert_list = crl.CertificateList.load(f.read())
        serial_numbers = []
        for revoked_cert in cert_list['tbs_cert_list']['revoked_certificates']:
            serial_numbers.append(revoked_cert['user_certificate'].native)
        self.assertEqual(
            15752,
            len(serial_numbers)
        )
        for serial_number in serial_numbers:
            self.assertIsInstance(
                serial_number,
                num_cls
            )
