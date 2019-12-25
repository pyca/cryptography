# -*- coding: utf-8 -*-
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend


def load_test_pem(filename):
    wd = os.path.dirname(os.path.abspath(__file__))
    prefix = os.path.join(wd, 'data')
    pem_data = open(os.path.join(prefix, filename), 'rb').read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())


class TestCorrectChainVerifies(object):

    def test_correct_3link_chain(self):

        leaf = load_test_pem('correct_3link_chain-leaf.pem')
        intermediate = load_test_pem('correct_3link_chain-intermediate.pem')
        trusted_root = load_test_pem('correct_3link_chain-root.pem')

        chains = leaf.verify(intermediates=[intermediate],
                             trusted_roots=[trusted_root],
                             cert_verif_cb=lambda: True)

        assert len(chains) == 1
        chain = chains[0]
        assert len(chain) == 3
        assert chain[0] == leaf
        assert chain[1] == intermediate
        assert chain[2] == trusted_root
