# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from asn1crypto import csr, util
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


class CSRTests(unittest.TestCase):

    def test_parse_csr(self):
        with open(os.path.join(fixtures_dir, 'test-inter-der.csr'), 'rb') as f:
            certification_request = csr.CertificationRequest.load(f.read())

        cri = certification_request['certification_request_info']

        self.assertEqual(
            'v1',
            cri['version'].native
        )

        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing Intermediate'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            cri['subject'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsa'),
                ('parameters', None),
            ]),
            cri['subject_pk_info']['algorithm'].native
        )
        self.assertEqual(
            24141757533938720807477509823483015516687050697622322097001928034085434547050399731881871694642845241206788286795830006142635608141713689209738431462004600429798152826994774062467402648660593454536565119527837471261495586474194846971065722669734666949739228862107500673350843489920495869942508240779131331715037662761414997889327943217889802893638175792326783316531272170879284118280173511200768884738639370318760377047837471530387161553030663446359575963736475504659902898072137674205021477968813148345198711103071746476009234601299344030395455052526948041544669303473529511160643491569274897838845918784633403435929,  # noqa
            cri['subject_pk_info']['public_key'].parsed['modulus'].native
        )
        self.assertEqual(
            65537,
            cri['subject_pk_info']['public_key'].parsed['public_exponent'].native
        )
        self.assertEqual(
            [],
            cri['attributes'].native
        )

    def test_parse_csr2(self):
        with open(os.path.join(fixtures_dir, 'test-third-der.csr'), 'rb') as f:
            certification_request = csr.CertificationRequest.load(f.read())

        cri = certification_request['certification_request_info']

        self.assertEqual(
            'v1',
            cri['version'].native
        )

        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Test Third-Level Certificate'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            cri['subject'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsa'),
                ('parameters', None),
            ]),
            cri['subject_pk_info']['algorithm'].native
        )
        self.assertEqual(
            24242772097421005542208203320016703216069397492249392798445262959177221203301502279838173203064357049006693856302147277901773700963054800321566171864477088538775137040886151390015408166478059887940234405152693144166884492162723776487601158833605063151869850475289834250129252480954724818505034734280077580919995584375189497366089269712298471489896645221362055822887892887126082288043106492130176555423739906252380437817155678204772878611148787130925042126257401487070141904017757131876614711613405231164930930771261221451019736883391322299033324412671768599041417705072563016759224152503535867541947310239343903761461,  # noqa
            cri['subject_pk_info']['public_key'].parsed['modulus'].native
        )
        self.assertEqual(
            65537,
            cri['subject_pk_info']['public_key'].parsed['public_exponent'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('type', 'extension_request'),
                    (
                        'values',
                        [
                            [
                                util.OrderedDict([
                                    ('extn_id', 'basic_constraints'),
                                    ('critical', False),
                                    (
                                        'extn_value',
                                        util.OrderedDict([
                                            ('ca', False),
                                            ('path_len_constraint', None),
                                        ])
                                    ),
                                ]),
                                util.OrderedDict([
                                    ('extn_id', 'key_usage'),
                                    ('critical', False),
                                    (
                                        'extn_value',
                                        set(['digital_signature', 'non_repudiation', 'key_encipherment']),
                                    ),
                                ])
                            ]
                        ]
                    ),
                ]),
            ],
            cri['attributes'].native
        )
