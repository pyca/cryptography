# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from asn1crypto import algos, core
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


class AlgoTests(unittest.TestCase):

    def test_signed_digest_parameters(self):
        sha256_rsa = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
        self.assertEqual(core.Null, sha256_rsa['parameters'].__class__)

    def test_digest_parameters(self):
        sha1 = algos.DigestAlgorithm({'algorithm': 'sha1'})
        self.assertEqual(core.Null, sha1['parameters'].__class__)

    def test_ccm_parameters(self):
        with open(os.path.join(fixtures_dir, 'aesccm_algo.der'), 'rb') as f:
            # PBES2 AlgorithmIdentifier
            algo = algos.EncryptionAlgorithm().load(f.read())
        scheme = algo['parameters']['encryption_scheme']
        self.assertEqual(scheme['parameters'].__class__, algos.CcmParams)
        self.assertEqual(scheme['parameters']['aes_nonce'].__class__, core.OctetString)
        self.assertEqual(scheme['parameters']['aes_nonce'].native, b'z\xb7\xbd\xb7\xe1\xc6\xc0\x11\xc1?\xf00')
        self.assertEqual(scheme['parameters']['aes_icvlen'].__class__, core.Integer)
        self.assertEqual(scheme['parameters']['aes_icvlen'].native, 8)
