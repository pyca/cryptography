# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os
from datetime import datetime

from asn1crypto import x509, core, pem, util

from .unittest_data import data_decorator, data
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


@data_decorator
class X509Tests(unittest.TestCase):

    def _load_cert(self, relative_path):
        with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            return x509.Certificate.load(cert_bytes)

    @staticmethod
    def is_valid_domain_ip_info():
        return (
            (
                'geotrust_certs/codex.crt',
                'codexns.io',
                True
            ),
            (
                'geotrust_certs/codex.crt',
                'dev.codexns.io',
                True
            ),
            (
                'geotrust_certs/codex.crt',
                'rc.codexns.io',
                True
            ),
            (
                'geotrust_certs/codex.crt',
                'foo.codexns.io',
                False
            ),
            (
                'geotrust_certs/codex.crt',
                '1.2.3.4',
                False
            ),
            (
                'geotrust_certs/codex.crt',
                '1::1',
                False
            ),
        )

    @data('is_valid_domain_ip_info')
    def is_valid_domain_ip(self, cert, domain_ip, result):
        cert = self._load_cert(cert)
        self.assertEqual(result, cert.is_valid_domain_ip(domain_ip))

    @staticmethod
    def ip_address_info():
        return (
            (
                '127.0.0.1',
                b'\x04\x04\x7F\x00\x00\x01'
            ),
            (
                '255.255.255.255',
                b'\x04\x04\xFF\xFF\xFF\xFF'
            ),
            (
                '127.0.0.1/28',
                b'\x04\x08\x7F\x00\x00\x01\xFF\xFF\xFF\xF0'
            ),
            (
                '255.255.255.255/0',
                b'\x04\x08\xFF\xFF\xFF\xFF\x00\x00\x00\x00'
            ),
            (
                'af::ed',
                b'\x04\x10\x00\xAF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xED'
            ),
            (
                'af::ed/128',
                b'\x04\x20\x00\xAF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\xED\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
            ),
            (
                'af::ed/0',
                b'\x04\x20\x00\xAF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\xED\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ),
        )

    @data('ip_address_info')
    def ip_address(self, unicode_string, der_bytes):
        self.assertEqual(der_bytes, x509.IPAddress(unicode_string).dump())
        self.assertEqual(unicode_string, x509.IPAddress.load(der_bytes).native)

    def test_dnsname(self):
        e = x509.DNSName('example.com')
        self.assertEqual('example.com', e.native)
        self.assertEqual('example.com', e.__unicode__())
        self.assertEqual(b'\x16\x0Bexample.com', e.dump())

    def test_indef_dnsname(self):
        e = x509.DNSName.load(b'\x36\x80\x16\x04exam\x16\x07ple.com\x00\x00')
        self.assertEqual('example.com', e.native)
        self.assertEqual('example.com', e.__unicode__())
        self.assertEqual(b'\x16\x0Bexample.com', e.dump(force=True))

    def test_dnsname_begin_dot(self):
        self.assertEqual(b'\x16\x03.gr', x509.DNSName('.gr').dump())

    @staticmethod
    def compare_dnsname_info():
        return (
            (
                'google.com',
                'google.com',
                True
            ),
            (
                'google.com',
                'Google.com',
                True
            ),
            (
                'Bücher.ch',
                b'\x16\x10xn--bcher-kva.ch',
                True
            ),
            (
                'google.com',
                b'\x16\x0AGoogle.com',
                True
            ),
            (
                'google.com',
                b'\x16\x09Google.co',
                False
            ),
        )

    @data('compare_dnsname_info')
    def compare_dnsname(self, domain_one, domain_two, equal):
        one = x509.DNSName(domain_one)
        if isinstance(domain_two, byte_cls):
            two = x509.DNSName.load(domain_two)
        else:
            two = x509.DNSName(domain_two)
        if equal:
            self.assertEqual(one, two)
        else:
            self.assertNotEqual(one, two)

    def test_uri(self):
        u = x509.URI('https://example.com')
        self.assertEqual('https://example.com', u.native)
        self.assertEqual('https://example.com', u.__unicode__())
        self.assertEqual(b'\x16\x13https://example.com', u.dump())

    def test_uri_no_normalization(self):
        u = x509.URI('https://example.com/')
        self.assertEqual('https://example.com/', u.native)
        self.assertEqual('https://example.com/', u.__unicode__())
        self.assertEqual(b'\x16\x14https://example.com/', u.dump())
        u2 = x509.URI('https://example.com')
        self.assertEqual('https://example.com', u2.native)
        self.assertEqual('https://example.com', u2.__unicode__())
        self.assertEqual(b'\x16\x13https://example.com', u2.dump())
        u3 = x509.URI('https://example.com:443/')
        self.assertEqual('https://example.com:443/', u3.native)
        self.assertEqual('https://example.com:443/', u3.__unicode__())
        self.assertEqual(b'\x16\x18https://example.com:443/', u3.dump())

    def test_indef_uri(self):
        u = x509.URI.load(b'\x36\x80\x16\x07https:/\x16\x07/exampl\x16\x05e.com\x00\x00')
        self.assertEqual('https://example.com', u.native)
        self.assertEqual('https://example.com', u.__unicode__())
        self.assertEqual(b'\x16\x13https://example.com', u.dump(force=True))

    @staticmethod
    def compare_uri_info():
        return (
            (
                'http://google.com',
                'http://google.com',
                True
            ),
            (
                'http://google.com/',
                'http://Google.com',
                True
            ),
            (
                'http://google.com:80',
                'http://google.com',
                True
            ),
            (
                'https://google.com',
                'https://google.com:443/',
                True
            ),
            (
                'http://google.com/%41%42%43',
                'http://google.com/ABC',
                True
            ),
            (
                'http://google.com/%41%42%43',
                'http://google.com/abc',
                False
            ),
            (
                'http://google.com/%41%42%43/',
                'http://google.com/ABC%2F',
                False
            ),
        )

    @data('compare_uri_info')
    def compare_uri(self, uri_one, uri_two, equal):
        one = x509.URI(uri_one)
        if isinstance(uri_two, byte_cls):
            two = x509.URI.load(uri_two)
        else:
            two = x509.URI(uri_two)
        if equal:
            self.assertEqual(one, two)
        else:
            self.assertNotEqual(one, two)

    def test_email_address(self):
        e = x509.EmailAddress('john@example.com')
        self.assertEqual('john@example.com', e.native)
        self.assertEqual('john@example.com', e.__unicode__())
        self.assertEqual(b'\x16\x10john@example.com', e.dump())

    def test_indef_email_address(self):
        e = x509.EmailAddress.load(b'\x36\x80\x16\x07john@ex\x16\x09ample.com\x00\x00')
        self.assertEqual('john@example.com', e.native)
        self.assertEqual('john@example.com', e.__unicode__())
        self.assertEqual(b'\x16\x10john@example.com', e.dump(force=True))

    @staticmethod
    def compare_email_address_info():
        return (
            (
                'john@google.com',
                'john@google.com',
                True
            ),
            (
                'john@google.com',
                'john@Google.com',
                True
            ),
            (
                'john@google.com',
                'John@google.com',
                False
            ),
            (
                'john@Bücher.ch',
                b'\x16\x15john@xn--bcher-kva.ch',
                True
            ),
            (
                'John@Bücher.ch',
                b'\x16\x15john@xn--bcher-kva.ch',
                False
            ),
            (
                'john@google.com',
                b'\x16\x0Fjohn@Google.com',
                True
            ),
            (
                'john@google.com',
                b'\x16\x0FJohn@google.com',
                False
            ),
            (
                'john@google.com',
                b'\x16\x0Ejohn@Google.co',
                False
            ),
        )

    @data('compare_email_address_info')
    def compare_email_address(self, email_one, email_two, equal):
        one = x509.EmailAddress(email_one)
        if isinstance(email_two, byte_cls):
            two = x509.EmailAddress.load(email_two)
        else:
            two = x509.EmailAddress(email_two)
        if equal:
            self.assertEqual(one, two)
        else:
            self.assertNotEqual(one, two)

    @staticmethod
    def compare_ip_address_info():
        return (
            (
                '127.0.0.1',
                '127.0.0.1',
                True
            ),
            (
                '127.0.0.1',
                '127.0.0.2',
                False
            ),
            (
                '127.0.0.1',
                '127.0.0.1/32',
                False
            ),
            (
                '127.0.0.1/32',
                b'\x04\x08\x7F\x00\x00\x01\xFF\xFF\xFF\xFF',
                True
            ),
            (
                '127.0.0.1',
                b'\x04\x08\x7F\x00\x00\x01\xFF\xFF\xFF\xFF',
                False
            ),
        )

    @data('compare_ip_address_info')
    def compare_ip_address(self, email_one, email_two, equal):
        one = x509.IPAddress(email_one)
        if isinstance(email_two, byte_cls):
            two = x509.IPAddress.load(email_two)
        else:
            two = x509.IPAddress(email_two)
        if equal:
            self.assertEqual(one, two)
        else:
            self.assertNotEqual(one, two)

    def test_dump_generalname(self):
        data = b'0.\x82\x0fsuscerte.gob.ve\xa0\x1b\x06\x05`\x86^\x02\x02\xa0\x12\x0c\x10RIF-G-20004036-0'
        alt = x509.GeneralNames.load(data)
        self.assertEqual(data, alt.dump(force=True))

    @staticmethod
    def compare_name_info():
        return (
            (
                True,
                x509.Name.build({
                    'common_name': 'Will Bond'
                }),
                x509.Name.build({
                    'common_name': 'will bond'
                })
            ),
            (
                True,
                x509.Name.build({
                    'common_name': 'Will Bond'
                }),
                x509.Name.build({
                    'common_name': 'will\tbond'
                })
            ),
            (
                True,
                x509.Name.build({
                    'common_name': 'Will Bond'
                }),
                x509.Name.build({
                    'common_name': 'Will Bond \U0001D173\U000E007F'
                })
            ),
            (
                True,
                x509.Name.build({
                    '2.5.4.3': 'Will Bond',
                }),
                x509.Name.build({
                    'common_name': 'Will Bond',
                }),
            ),
            (
                True,
                x509.Name.build({
                    '2.5.4.6': 'US',
                    'common_name': 'Will Bond'
                }),
                x509.Name.build({
                    'country_name': 'US',
                    'common_name': 'Will Bond'
                })
            ),
            (
                False,
                x509.Name.build({
                    'common_name': 'Will Bond',
                    '0.9.2342.19200300.100.1.1': 'wbond'
                }),
                x509.Name.build({
                    'common_name': 'Will Bond',
                }),
            ),
            (
                False,
                x509.Name.build({
                    'country_name': 'US',
                    'common_name': 'Will Bond'
                }),
                x509.Name.build({
                    'country_name': 'US',
                    'state_or_province_name': 'Massachusetts',
                    'common_name': 'Will Bond'
                })
            ),
        )

    @data('compare_name_info')
    def compare_name(self, are_equal, general_name_1, general_name_2):
        if are_equal:
            self.assertEqual(general_name_1, general_name_2)
        else:
            self.assertNotEqual(general_name_1, general_name_2)

    def test_build_name_printable(self):
        utf8_name = x509.Name.build(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'common_name': 'Will Bond'
            }
        )
        self.assertIsInstance(utf8_name.chosen[2][0]['value'].chosen, core.UTF8String)
        self.assertEqual('common_name', utf8_name.chosen[2][0]['type'].native)
        printable_name = x509.Name.build(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'common_name': 'Will Bond'
            },
            use_printable=True
        )
        self.assertIsInstance(printable_name.chosen[2][0]['value'].chosen, core.PrintableString)
        self.assertEqual('common_name', printable_name.chosen[2][0]['type'].native)

    def test_v1_cert(self):
        cert = self._load_cert('chromium/ndn.ca.crt')
        tbs_cert = cert['tbs_certificate']
        self.assertEqual('v1', tbs_cert['version'].native)
        self.assertEqual(15832340745319036834, tbs_cert['serial_number'].native)
        self.assertEqual(
            'Email Address: support@dreamhost.com; Common Name: New Dream Network Certificate Authority; '
            'Organizational Unit: Security; Organization: New Dream Network, LLC; Locality: Los Angeles; '
            'State/Province: California; Country: US',
            tbs_cert['issuer'].human_friendly
        )
        self.assertEqual(
            'Email Address: support@dreamhost.com; Common Name: New Dream Network Certificate Authority; '
            'Organizational Unit: Security; Organization: New Dream Network, LLC; Locality: Los Angeles; '
            'State/Province: California; Country: US',
            tbs_cert['subject'].human_friendly
        )

    def test_subject_alt_name_variations(self):
        cert = self._load_cert('chromium/subjectAltName_sanity_check.pem')
        alt_names = cert.subject_alt_name_value
        for general_name in alt_names:
            self.assertIsInstance(general_name, x509.GeneralName)
        self.assertIsInstance(alt_names[0].chosen, x509.IPAddress)
        self.assertEqual(alt_names[0].chosen.native, '127.0.0.2')
        self.assertIsInstance(alt_names[1].chosen, x509.IPAddress)
        self.assertEqual(alt_names[1].chosen.native, 'fe80::1')
        self.assertIsInstance(alt_names[2].chosen, x509.DNSName)
        self.assertEqual(alt_names[2].chosen.native, 'test.example')
        self.assertIsInstance(alt_names[3].chosen, x509.EmailAddress)
        self.assertEqual(alt_names[3].chosen.native, 'test@test.example')
        self.assertIsInstance(alt_names[4].chosen, x509.AnotherName)
        self.assertEqual(alt_names[4].chosen.native, util.OrderedDict([('type_id', '1.2.3.4'), ('value', 'ignore me')]))
        self.assertIsInstance(alt_names[5].chosen, x509.Name)
        self.assertEqual(alt_names[5].chosen.native, util.OrderedDict([('common_name', '127.0.0.3')]))

    def test_sha1_fingerprint(self):
        cert = self._load_cert('geotrust_certs/codex.crt')
        self.assertEqual('78 1C 9F 87 59 93 52 08 D2 21 FA 70 6C C5 F9 76 12 C9 6D 8B', cert.sha1_fingerprint)

    def test_sha256_fingerprint(self):
        cert = self._load_cert('geotrust_certs/codex.crt')
        self.assertEqual(
            'E5 6D 97 3A 22 77 55 E4 85 6F 71 78 DA 4D 69 93 0C E2 87 F8 85 5E BE 1A 8C F7 FE 78 80 EB A5 F0',
            cert.sha256_fingerprint)

    def test_punycode_common_name(self):
        cert = self._load_cert('chromium/punycodetest.pem')
        self.assertEqual('xn--wgv71a119e.com', cert['tbs_certificate']['subject'].native['common_name'])

    @staticmethod
    def signature_algo_info():
        return (
            (
                'keys/test-der.crt',
                'rsassa_pkcs1v15',
                'sha256'
            ),
            (
                'keys/test-inter-der.crt',
                'rsassa_pkcs1v15',
                'sha256'
            ),
            (
                'keys/test-dsa-der.crt',
                'dsa',
                'sha256'
            ),
            (
                'keys/test-third-der.crt',
                'rsassa_pkcs1v15',
                'sha256'
            ),
            (
                'keys/test-ec-der.crt',
                'ecdsa',
                'sha256'
            ),
            (
                'keys/test-rsapss.crt',
                'rsassa_pss',
                'sha256'
            ),
        )

    @data('signature_algo_info')
    def signature_algo(self, relative_path, signature_algo, hash_algo):
        cert = self._load_cert(relative_path)
        self.assertEqual(signature_algo, cert['signature_algorithm'].signature_algo)
        self.assertEqual(hash_algo, cert['signature_algorithm'].hash_algo)

    @staticmethod
    def critical_extensions_info():
        return (
            (
                'keys/test-der.crt',
                set()
            ),
            (
                'keys/test-inter-der.crt',
                set()
            ),
            (
                'keys/test-third-der.crt',
                set()
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                set(['basic_constraints', 'key_usage'])
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                set(['basic_constraints', 'key_usage'])
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                set(['basic_constraints', 'key_usage'])
            ),
            (
                'geotrust_certs/codex.crt',
                set(['key_usage'])
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                set(['key_usage', 'basic_constraints'])
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                set(['key_usage', 'basic_constraints'])
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                set(['key_usage', 'basic_constraints'])
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                set(['basic_constraints', 'key_usage'])
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                set(['basic_constraints', 'key_usage'])
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                set(['key_usage', 'extended_key_usage', 'basic_constraints'])
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                set(['key_usage', 'extended_key_usage', 'basic_constraints'])
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                set(['key_usage', 'extended_key_usage', 'basic_constraints'])
            ),
            (
                'rfc3739.crt',
                set(['key_usage'])
            ),
        )

    @data('critical_extensions_info')
    def critical_extensions(self, relative_path, critical_extensions):
        cert = self._load_cert(relative_path)
        self.assertEqual(critical_extensions, cert.critical_extensions)

    @staticmethod
    def subject_directory_attributes_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                None
            ),
            (
                'geotrust_certs/codex.crt',
                None
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                None
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                None
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                None
            ),
            (
                'rfc3739.crt',
                [
                    util.OrderedDict([('type', 'pda_country_of_citizenship'), ('values', ['DE'])]),
                    util.OrderedDict([('type', 'pda_gender'), ('values', ['F'])]),
                    util.OrderedDict([('type', 'pda_date_of_birth'), ('values', [
                        datetime(1971, 10, 14, 12, 0, tzinfo=util.timezone.utc)])]),
                    util.OrderedDict([('type', 'pda_place_of_birth'), ('values', ['Darmstadt'])]),
                ]
            ),
        )

    @data('subject_directory_attributes_value_info')
    def subject_directory_attributes_value(self, relative_path, sda_value):
        cert = self._load_cert(relative_path)
        value = cert.subject_directory_attributes_value
        self.assertEqual(sda_value, value.native if value else None)

    @staticmethod
    def key_identifier_value_info():
        return (
            (
                'keys/test-der.crt',
                b'\xbeB\x85=\xcc\xff\xe3\xf9(\x02\x8f~XV\xb4\xfd\x03\\\xeaK'
            ),
            (
                'keys/test-inter-der.crt',
                b'\xd2\n\xfd.%\xd1\xb7!\xd7P~\xbb\xa4}\xbf4\xefR^\x02'
            ),
            (
                'keys/test-third-der.crt',
                b'D8\xe0\xe0&\x85\xbf\x98\x86\xdc\x1b\xe1\x1d\xf520\xbe\xab\xac\r'
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                b'\xda\xbb.\xaa\xb0\x0c\xb8\x88&Qt\\m\x03\xd3\xc0\xd8\x8fz\xd6'
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                b',\xd5PA\x97\x15\x8b\xf0\x8f6a[J\xfbk\xd9\x99\xc93\x92'
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                b'\xde\xcf\\P\xb7\xae\x02\x1f\x15\x17\xaa\x16\xe8\r\xb5(\x9djZ\xf3'
            ),
            (
                'geotrust_certs/codex.crt',
                None
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                b'y\xb4Y\xe6{\xb6\xe5\xe4\x01s\x80\x08\x88\xc8\x1aX\xf6\xe9\x9bn'
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                b'\xa8Jjc\x04}\xdd\xba\xe6\xd19\xb7\xa6Ee\xef\xf3\xa8\xec\xa1'
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                b'\xc5\xb1\xabNL\xb1\xcdd0\x93~\xc1\x84\x99\x05\xab\xe6\x03\xe2%'
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                b"'\xf8/\xe9]\xd7\r\xf4\xa8\xea\x87\x99=\xfd\x8e\xb3\x9e@\xd0\x91"
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                b'd|\\\xe1\xe0`8NH\x9f\x05\xbcUc~?\xaeM\xf7\x1e'
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                b'\x94a\x04\x92\x04L\xe6\xffh\xa8\x96\xafy\xd2\xf32\x84\xae[\xcf'
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                b'\xd2\xb7\x15\x7fd0\x07(p\x83\xca(\xfa\x88\x96\xde\x9e\xfc\x8a='
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                b'G\xde\xa4\xe7\xea`\xe7\xee6\xc8\xf1\xd5\xb0F\x07\x07\x9eBh\xce'
            ),
            (
                'rfc3739.crt',
                None
            ),
        )

    @data('key_identifier_value_info')
    def key_identifier_value(self, relative_path, key_identifier_value):
        cert = self._load_cert(relative_path)
        value = cert.key_identifier_value
        self.assertEqual(key_identifier_value, value.native if value else None)

    @staticmethod
    def key_usage_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                set(['digital_signature', 'key_cert_sign', 'crl_sign'])
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                set(['key_cert_sign', 'crl_sign'])
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                set(['key_cert_sign', 'crl_sign'])
            ),
            (
                'geotrust_certs/codex.crt',
                set(['digital_signature', 'key_encipherment'])
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                set(['key_cert_sign', 'crl_sign'])
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                set(['digital_signature', 'key_cert_sign', 'crl_sign'])
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                set(['digital_signature', 'key_cert_sign', 'crl_sign'])
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                set(['key_cert_sign', 'crl_sign'])
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                set(['key_cert_sign', 'crl_sign'])
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                set(['digital_signature', 'key_encipherment'])
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                set(['digital_signature', 'key_encipherment'])
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                set(['digital_signature', 'key_encipherment'])
            ),
            (
                'rfc3739.crt',
                set(['non_repudiation'])
            ),
        )

    @data('key_usage_value_info')
    def key_usage_value(self, relative_path, key_usage_value):
        cert = self._load_cert(relative_path)
        value = cert.key_usage_value
        self.assertEqual(key_usage_value, value.native if value else None)

    @staticmethod
    def subject_alt_name_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                [
                    util.OrderedDict([
                        ('common_name', 'SymantecPKI-1-538')
                    ])
                ]
            ),
            (
                'geotrust_certs/codex.crt',
                ['dev.codexns.io', 'rc.codexns.io', 'packagecontrol.io', 'wbond.net', 'codexns.io']
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                None
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                None
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                ['anything.example.com']
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                ['anything.example.com']
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                None
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('subject_alt_name_value_info')
    def subject_alt_name_value(self, relative_path, subject_alt_name_value):
        cert = self._load_cert(relative_path)
        value = cert.subject_alt_name_value
        self.assertEqual(subject_alt_name_value, value.native if value else None)

    @staticmethod
    def basic_constraints_value_info():
        return (
            (
                'keys/test-der.crt',
                {'ca': True, 'path_len_constraint': None}
            ),
            (
                'keys/test-inter-der.crt',
                {'ca': True, 'path_len_constraint': None}
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                {'ca': True, 'path_len_constraint': None}
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                {'ca': True, 'path_len_constraint': None}
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                {'ca': True, 'path_len_constraint': 0}
            ),
            (
                'geotrust_certs/codex.crt',
                {'ca': False, 'path_len_constraint': None}
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                {'ca': True, 'path_len_constraint': None}
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                {'ca': True, 'path_len_constraint': 0}
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                {'ca': True, 'path_len_constraint': 0}
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                {'ca': True, 'path_len_constraint': None}
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                {'ca': True, 'path_len_constraint': None}
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                {'ca': False, 'path_len_constraint': None}
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                {'ca': False, 'path_len_constraint': None}
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                {'ca': False, 'path_len_constraint': None}
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('basic_constraints_value_info')
    def basic_constraints_value(self, relative_path, basic_constraints_value):
        cert = self._load_cert(relative_path)
        value = cert.basic_constraints_value
        self.assertEqual(basic_constraints_value, value.native if value else None)

    @staticmethod
    def name_constraints_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                None
            ),
            (
                'geotrust_certs/codex.crt',
                None
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                None
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                util.OrderedDict([
                    (
                        'permitted_subtrees',
                        [
                            util.OrderedDict([
                                ('base', 'onlythis.com'),
                                ('minimum', 0),
                                ('maximum', None)
                            ]),
                            util.OrderedDict([
                                (
                                    'base',
                                    util.OrderedDict([
                                        ('country_name', 'US'),
                                        ('state_or_province_name', 'MA'),
                                        ('locality_name', 'Boston'),
                                        ('organization_name', 'Example LLC')
                                    ])
                                ),
                                ('minimum', 0),
                                ('maximum', None)
                            ])
                        ]
                    ),
                    (
                        'excluded_subtrees',
                        [
                            util.OrderedDict([
                                ('base', '0.0.0.0/0'),
                                ('minimum', 0),
                                ('maximum', None)
                            ]),
                            util.OrderedDict([
                                ('base', '::/0'),
                                ('minimum', 0),
                                ('maximum', None)
                            ])
                        ]
                    ),
                ])
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                None
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('name_constraints_value_info')
    def name_constraints_value(self, relative_path, name_constraints_value):
        cert = self._load_cert(relative_path)
        value = cert.name_constraints_value
        self.assertEqual(name_constraints_value, value.native if value else None)

    @staticmethod
    def crl_distribution_points_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://g1.symcb.com/GeoTrustPCA.crl']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'geotrust_certs/codex.crt',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://gm.symcb.com/gm.crl']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://crl.root-x1.letsencrypt.org']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://crl.root-x1.letsencrypt.org']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://crl.globalsign.com/gs/trustrootcatg2.crl']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]),
            (
                'globalsign_example_keys/rootCA.cer',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://crl.globalsign.com/gs/trustrootcatg2.crl']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]),
            (
                'globalsign_example_keys/SSL1.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                None
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('crl_distribution_points_value_info')
    def crl_distribution_points_value(self, relative_path, crl_distribution_points_value):
        cert = self._load_cert(relative_path)
        value = cert.crl_distribution_points_value
        self.assertEqual(crl_distribution_points_value, value.native if value else None)

    @staticmethod
    def certificate_policies_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                [
                    util.OrderedDict([
                        ('policy_identifier', 'any_policy'),
                        (
                            'policy_qualifiers',
                            [
                                util.OrderedDict([
                                    ('policy_qualifier_id', 'certification_practice_statement'),
                                    ('qualifier', 'https://www.geotrust.com/resources/cps')
                                ])
                            ]
                        )
                    ])
                ]
            ),
            (
                'geotrust_certs/codex.crt',
                [
                    util.OrderedDict([
                        ('policy_identifier', '1.3.6.1.4.1.14370.1.6'),
                        (
                            'policy_qualifiers',
                            [
                                util.OrderedDict([
                                    ('policy_qualifier_id', 'certification_practice_statement'),
                                    ('qualifier', 'https://www.geotrust.com/resources/repository/legal')
                                ]),
                                util.OrderedDict([
                                    ('policy_qualifier_id', 'user_notice'),
                                    (
                                        'qualifier',
                                        util.OrderedDict([
                                            ('notice_ref', None),
                                            ('explicit_text', 'https://www.geotrust.com/resources/repository/legal')
                                        ])
                                    )
                                ])
                            ]
                        )
                    ])
                ]
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                [
                    util.OrderedDict([
                        ('policy_identifier', '2.23.140.1.2.1'),
                        ('policy_qualifiers', None)
                    ]),
                    util.OrderedDict([
                        ('policy_identifier', '1.3.6.1.4.1.44947.1.1.1'),
                        (
                            'policy_qualifiers',
                            [
                                util.OrderedDict([
                                    ('policy_qualifier_id', 'certification_practice_statement'),
                                    ('qualifier', 'http://cps.root-x1.letsencrypt.org')
                                ])
                            ]
                        )
                    ])
                ]
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                [
                    util.OrderedDict([
                        ('policy_identifier', '2.23.140.1.2.1'),
                        ('policy_qualifiers', None)
                    ]),
                    util.OrderedDict([
                        ('policy_identifier', '1.3.6.1.4.1.44947.1.1.1'),
                        (
                            'policy_qualifiers',
                            [
                                util.OrderedDict([
                                    ('policy_qualifier_id', 'certification_practice_statement'),
                                    ('qualifier', 'http://cps.root-x1.letsencrypt.org')
                                ])
                            ]
                        )
                    ])
                ]
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                [
                    util.OrderedDict([
                        ('policy_identifier', '1.3.6.1.4.1.4146.1.60'),
                        (
                            'policy_qualifiers',
                            [
                                util.OrderedDict([
                                    ('policy_qualifier_id', 'certification_practice_statement'),
                                    ('qualifier', 'https://www.globalsign.com/repository/')
                                ])
                            ]
                        )
                    ])
                ]
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                [
                    util.OrderedDict([
                        ('policy_identifier', '1.3.6.1.4.1.4146.1.60'),
                        (
                            'policy_qualifiers',
                            [
                                util.OrderedDict([
                                    ('policy_qualifier_id', 'certification_practice_statement'),
                                    ('qualifier', 'https://www.globalsign.com/repository/')
                                ])
                            ]
                        )
                    ])
                ]
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                [
                    util.OrderedDict([
                        ('policy_identifier', '1.3.6.1.4.1.4146.1.60'),
                        (
                            'policy_qualifiers',
                            [
                                util.OrderedDict([
                                    ('policy_qualifier_id', 'certification_practice_statement'),
                                    ('qualifier', 'https://www.globalsign.com/repository/')
                                ])
                            ]
                        )
                    ])
                ]
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                [
                    util.OrderedDict([
                        ('policy_identifier', '1.3.6.1.4.1.4146.1.60'),
                        (
                            'policy_qualifiers',
                            [
                                util.OrderedDict([
                                    ('policy_qualifier_id', 'certification_practice_statement'),
                                    ('qualifier', 'https://www.globalsign.com/repository/')
                                ])
                            ]
                        )
                    ])
                ]
            ),
            (
                'rfc3739.crt',
                [
                    util.OrderedDict([
                        ('policy_identifier', '1.3.36.8.1.1'),
                        ('policy_qualifiers', None)
                    ]),
                ]
            ),
        )

    @data('certificate_policies_value_info')
    def certificate_policies_value(self, relative_path, certificate_policies_value):
        cert = self._load_cert(relative_path)
        value = cert.certificate_policies_value
        self.assertEqual(certificate_policies_value, value.native if value else None)

    @staticmethod
    def policy_mappings_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                None
            ),
            (
                'geotrust_certs/codex.crt',
                None
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                None
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                None
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                None
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('policy_mappings_value_info')
    def policy_mappings_value(self, relative_path, policy_mappings_value):
        cert = self._load_cert(relative_path)
        value = cert.policy_mappings_value
        self.assertEqual(policy_mappings_value, value.native if value else None)

    @staticmethod
    def authority_key_identifier_value_info():
        return (
            (
                'keys/test-der.crt',
                util.OrderedDict([
                    ('key_identifier', b'\xbeB\x85=\xcc\xff\xe3\xf9(\x02\x8f~XV\xb4\xfd\x03\\\xeaK'),
                    (
                        'authority_cert_issuer',
                        [
                            util.OrderedDict([
                                ('country_name', 'US'),
                                ('state_or_province_name', 'Massachusetts'),
                                ('locality_name', 'Newbury'),
                                ('organization_name', 'Codex Non Sufficit LC'),
                                ('organizational_unit_name', 'Testing'),
                                ('common_name', 'Will Bond'),
                                ('email_address', 'will@codexns.io')
                            ])
                        ]
                    ),
                    ('authority_cert_serial_number', 13683582341504654466)
                ])
            ),
            (
                'keys/test-inter-der.crt',
                util.OrderedDict([
                    ('key_identifier', b'\xbeB\x85=\xcc\xff\xe3\xf9(\x02\x8f~XV\xb4\xfd\x03\\\xeaK'),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'keys/test-third-der.crt',
                util.OrderedDict([
                    ('key_identifier', b'\xd2\n\xfd.%\xd1\xb7!\xd7P~\xbb\xa4}\xbf4\xefR^\x02'),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                util.OrderedDict([
                    ('key_identifier', b'\xda\xbb.\xaa\xb0\x0c\xb8\x88&Qt\\m\x03\xd3\xc0\xd8\x8fz\xd6'),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                util.OrderedDict([
                    ('key_identifier', b',\xd5PA\x97\x15\x8b\xf0\x8f6a[J\xfbk\xd9\x99\xc93\x92'),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'geotrust_certs/codex.crt',
                util.OrderedDict([
                    ('key_identifier', b'\xde\xcf\\P\xb7\xae\x02\x1f\x15\x17\xaa\x16\xe8\r\xb5(\x9djZ\xf3'),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                util.OrderedDict([
                    ('key_identifier', b'y\xb4Y\xe6{\xb6\xe5\xe4\x01s\x80\x08\x88\xc8\x1aX\xf6\xe9\x9bn'),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                util.OrderedDict([
                    ('key_identifier', b'y\xb4Y\xe6{\xb6\xe5\xe4\x01s\x80\x08\x88\xc8\x1aX\xf6\xe9\x9bn'),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                util.OrderedDict([
                    ('key_identifier', b'd|\\\xe1\xe0`8NH\x9f\x05\xbcUc~?\xaeM\xf7\x1e'),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                util.OrderedDict([
                    ('key_identifier', b"'\xf8/\xe9]\xd7\r\xf4\xa8\xea\x87\x99=\xfd\x8e\xb3\x9e@\xd0\x91"),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                util.OrderedDict([
                    ('key_identifier', b"'\xf8/\xe9]\xd7\r\xf4\xa8\xea\x87\x99=\xfd\x8e\xb3\x9e@\xd0\x91"),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                util.OrderedDict([
                    ('key_identifier', b"'\xf8/\xe9]\xd7\r\xf4\xa8\xea\x87\x99=\xfd\x8e\xb3\x9e@\xd0\x91"),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
            (
                'rfc3739.crt',
                util.OrderedDict([
                    ('key_identifier', b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\xfe\xdc\xba\x98"),
                    ('authority_cert_issuer', None),
                    ('authority_cert_serial_number', None)
                ])
            ),
        )

    @data('authority_key_identifier_value_info')
    def authority_key_identifier_value(self, relative_path, authority_key_identifier_value):
        cert = self._load_cert(relative_path)
        value = cert.authority_key_identifier_value
        self.assertEqual(authority_key_identifier_value, value.native if value else None)

    @staticmethod
    def policy_constraints_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                None
            ),
            (
                'geotrust_certs/codex.crt',
                None
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                None
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                None
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                None
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('policy_constraints_value_info')
    def policy_constraints_value(self, relative_path, policy_constraints_value):
        cert = self._load_cert(relative_path)
        value = cert.policy_constraints_value
        self.assertEqual(policy_constraints_value, value.native if value else None)

    @staticmethod
    def extended_key_usage_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                None
            ),
            (
                'geotrust_certs/codex.crt',
                ['server_auth', 'client_auth']),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                None
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                None
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                ['server_auth', 'client_auth']
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                ['server_auth', 'client_auth']
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                ['server_auth', 'client_auth']
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('extended_key_usage_value_info')
    def extended_key_usage_value(self, relative_path, extended_key_usage_value):
        cert = self._load_cert(relative_path)
        value = cert.extended_key_usage_value
        self.assertEqual(extended_key_usage_value, value.native if value else None)

    @staticmethod
    def authority_information_access_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                [
                    util.OrderedDict([
                        ('access_method', 'ocsp'),
                        ('access_location', 'http://g2.symcb.com')
                    ])
                ]
            ),
            (
                'geotrust_certs/codex.crt',
                [
                    util.OrderedDict([
                        ('access_method', 'ocsp'),
                        ('access_location', 'http://gm.symcd.com')
                    ]),
                    util.OrderedDict([
                        ('access_method', 'ca_issuers'),
                        ('access_location', 'http://gm.symcb.com/gm.crt')
                    ]),
                ]
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                [
                    util.OrderedDict([
                        ('access_method', 'ocsp'),
                        ('access_location', 'http://ocsp.root-x1.letsencrypt.org/')
                    ]),
                    util.OrderedDict([
                        ('access_method', 'ca_issuers'),
                        ('access_location', 'http://cert.root-x1.letsencrypt.org/')
                    ])
                ]
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                [
                    util.OrderedDict([
                        ('access_method', 'ocsp'),
                        ('access_location', 'http://ocsp.root-x1.letsencrypt.org/')
                    ]),
                    util.OrderedDict([
                        ('access_method', 'ca_issuers'),
                        ('access_location', 'http://cert.root-x1.letsencrypt.org/')
                    ])
                ]
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                None
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                [
                    util.OrderedDict([
                        ('access_method', 'ocsp'),
                        ('access_location', 'http://ocsp.exampleovca.com/')
                    ]),
                    util.OrderedDict([
                        ('access_method', 'ca_issuers'),
                        ('access_location', 'http://secure.globalsign.com/cacert/trustrootcatg2.crt')
                    ])
                ]
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                [
                    util.OrderedDict([
                        ('access_method', 'ocsp'),
                        ('access_location', 'http://ocsp.exampleovca.com/')
                    ]),
                    util.OrderedDict([
                        ('access_method', 'ca_issuers'),
                        ('access_location', 'http://secure.globalsign.com/cacert/trustrootcatg2.crt')
                    ])
                ]
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                [
                    util.OrderedDict([
                        ('access_method', 'ocsp'),
                        ('access_location', 'http://ocsp.exampleovca.com/')
                    ]),
                    util.OrderedDict([
                        ('access_method', 'ca_issuers'),
                        ('access_location', 'http://secure.globalsign.com/cacert/trustrootcatg2.crt')
                    ])
                ]
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('authority_information_access_value_info')
    def authority_information_access_value(self, relative_path, authority_information_access_value):
        cert = self._load_cert(relative_path)
        value = cert.authority_information_access_value
        self.assertEqual(authority_information_access_value, value.native if value else None)

    @staticmethod
    def ocsp_no_check_value_info():
        return (
            (
                'keys/test-der.crt',
                None
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                None
            ),
            (
                'geotrust_certs/codex.crt',
                None
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                None
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                None
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                None
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('ocsp_no_check_value_info')
    def ocsp_no_check_value(self, relative_path, ocsp_no_check_value):
        cert = self._load_cert(relative_path)
        value = cert.ocsp_no_check_value
        self.assertEqual(ocsp_no_check_value, value.native if value else None)

    @staticmethod
    def private_key_usage_period_value_info():
        return (
            (
                'ocsp-with-pkup.pem',
                b'\x80\x0f20170918151736Z\x81\x0f20180101041421Z'
            ),
        )

    @data('private_key_usage_period_value_info')
    def private_key_usage_period_value(self, relative_path, private_key_usage_period_value):
        cert = self._load_cert(relative_path)
        self.assertEqual(private_key_usage_period_value, cert.private_key_usage_period_value.contents)

    @staticmethod
    def serial_number_info():
        return (
            (
                'keys/test-der.crt',
                13683582341504654466
            ),
            (
                'keys/test-inter-der.crt',
                1590137
            ),
            (
                'keys/test-third-der.crt',
                2474902313
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                1
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                32798226551256963324313806436981982369
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                146934555852773531829332059263122711876
            ),
            (
                'geotrust_certs/codex.crt',
                130338219198307073574879940486642352162
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                172886928669790476064670243504169061120
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                307817870430047279283060309415759825539
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                199666138109676817050168330923544141416
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                43543335419752
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                342514332211132
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                425155524522
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                425155524522
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                425155524522
            ),
            (
                'rfc3739.crt',
                1234567890,
            ),
        )

    @data('serial_number_info')
    def serial_number(self, relative_path, serial_number):
        cert = self._load_cert(relative_path)
        self.assertEqual(serial_number, cert.serial_number)

    @staticmethod
    def key_identifier_info():
        return (
            (
                'keys/test-der.crt',
                b'\xbeB\x85=\xcc\xff\xe3\xf9(\x02\x8f~XV\xb4\xfd\x03\\\xeaK'
            ),
            (
                'keys/test-inter-der.crt',
                b'\xd2\n\xfd.%\xd1\xb7!\xd7P~\xbb\xa4}\xbf4\xefR^\x02'
            ),
            (
                'keys/test-third-der.crt',
                b'D8\xe0\xe0&\x85\xbf\x98\x86\xdc\x1b\xe1\x1d\xf520\xbe\xab\xac\r'
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                b'\xda\xbb.\xaa\xb0\x0c\xb8\x88&Qt\\m\x03\xd3\xc0\xd8\x8fz\xd6'
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                b',\xd5PA\x97\x15\x8b\xf0\x8f6a[J\xfbk\xd9\x99\xc93\x92'
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                b'\xde\xcf\\P\xb7\xae\x02\x1f\x15\x17\xaa\x16\xe8\r\xb5(\x9djZ\xf3'
            ),
            (
                'geotrust_certs/codex.crt',
                None
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                b'y\xb4Y\xe6{\xb6\xe5\xe4\x01s\x80\x08\x88\xc8\x1aX\xf6\xe9\x9bn'
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                b'\xa8Jjc\x04}\xdd\xba\xe6\xd19\xb7\xa6Ee\xef\xf3\xa8\xec\xa1'
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                b'\xc5\xb1\xabNL\xb1\xcdd0\x93~\xc1\x84\x99\x05\xab\xe6\x03\xe2%'
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                b"'\xf8/\xe9]\xd7\r\xf4\xa8\xea\x87\x99=\xfd\x8e\xb3\x9e@\xd0\x91"
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                b'd|\\\xe1\xe0`8NH\x9f\x05\xbcUc~?\xaeM\xf7\x1e'
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                b'\x94a\x04\x92\x04L\xe6\xffh\xa8\x96\xafy\xd2\xf32\x84\xae[\xcf'
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                b'\xd2\xb7\x15\x7fd0\x07(p\x83\xca(\xfa\x88\x96\xde\x9e\xfc\x8a='
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                b'G\xde\xa4\xe7\xea`\xe7\xee6\xc8\xf1\xd5\xb0F\x07\x07\x9eBh\xce'
            ),
            (
                'rfc3739.crt',
                None,
            ),
        )

    @data('key_identifier_info')
    def key_identifier(self, relative_path, key_identifier):
        cert = self._load_cert(relative_path)
        self.assertEqual(key_identifier, cert.key_identifier)

    @staticmethod
    def issuer_serial_info():
        return (
            (
                'keys/test-der.crt',
                b'\xdd\x8a\x19x\xae`\x19=\xa7\xf8\x00\xb9\xfbx\xf8\xedu\xb8!\xf8\x8c'
                b'\xdb\x1f\x99\'7w\x93\xb4\xa4\'\xa0:13683582341504654466'
            ),
            (
                'keys/test-inter-der.crt',
                b'\xdd\x8a\x19x\xae`\x19=\xa7\xf8\x00\xb9\xfbx\xf8\xedu\xb8!\xf8\x8c'
                b'\xdb\x1f\x99\'7w\x93\xb4\xa4\'\xa0:1590137'
            ),
            (
                'keys/test-third-der.crt',
                b'\xed{\x9b\xbf\x9b\xdbd\xa4\xea\xf2#+H\x96\xcd\x80\x99\xf6\xecCM\x94'
                b'\x07\x02\xe2\x18\xf3\x83\x8c8%\x01:2474902313'
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                b'\xa1\x848\xf2\xe5w\xee\xec\xce\xfefJC+\xdf\x97\x7f\xd2Y\xe3\xdc\xa0D7~\x07\xd9\x9dzL@g:1'
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                b'\xdcg\x0c\x80\x03\xb3D\xa0v\xe2\xee\xec\x8b\xd6\x82\x01\xf0\x13\x0cwT'
                b'\xb4\x8f\x80\x0eT\x9d\xbf\xbf\xa4\x11\x80:32798226551256963324313806436981982369'
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                b'\xdcg\x0c\x80\x03\xb3D\xa0v\xe2\xee\xec\x8b\xd6\x82\x01\xf0\x13\x0cwT'
                b'\xb4\x8f\x80\x0eT\x9d\xbf\xbf\xa4\x11\x80:146934555852773531829332059263122711876'
            ),
            (
                'geotrust_certs/codex.crt',
                b'x\x12\xe0\x15\x00d;\xc3\xb9/\xf6\x13\n\xd8\xe2\xddY\xf7\xaf*=C\x01<\x86\xf5\x9f'
                b'_\xab;e\xd1:130338219198307073574879940486642352162'
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                b'\xf6\xdb/\xbd\x9d\xd8]\x92Y\xdd\xb3\xc6\xde}{/\xec?>\x0c\xef\x17a\xbc\xbf3 W\x1e'
                b'-0\xf8:172886928669790476064670243504169061120'
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                b'\xf6\xdb/\xbd\x9d\xd8]\x92Y\xdd\xb3\xc6\xde}{/\xec?>\x0c\xef\x17a\xbc\xbf3 W\x1e-'
                b'0\xf8:307817870430047279283060309415759825539'
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                b'\xf6\xdb/\xbd\x9d\xd8]\x92Y\xdd\xb3\xc6\xde}{/\xec?>\x0c\xef\x17a\xbc\xbf3 W\x1e-'
                b'0\xf8:199666138109676817050168330923544141416'
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                b'\xd2\xe7\xca\x10\xc1\x91\x92Y^A\x11\xd3Rz\xd5\x93\x19wk\x11\xef\xaa\x9c\xad\x10'
                b'\x8ak\x8a\x08-\x0c\xff:43543335419752'
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                b'\xd2\xe7\xca\x10\xc1\x91\x92Y^A\x11\xd3Rz\xd5\x93\x19wk\x11\xef\xaa\x9c\xad\x10'
                b'\x8ak\x8a\x08-\x0c\xff:342514332211132'
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                b'_\xc0S\xb1\xeb}\xe3\x8e\xe4{\xdb\xd7\xe2\xd9}=3\x97|\x0c\x1e\xecz\xcc\x92u\x1f'
                b'\xf0\x1d\xbc\x9f\xe4:425155524522'
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                b'_\xc0S\xb1\xeb}\xe3\x8e\xe4{\xdb\xd7\xe2\xd9}=3\x97|\x0c\x1e\xecz\xcc\x92u\x1f'
                b'\xf0\x1d\xbc\x9f\xe4:425155524522'
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                b'_\xc0S\xb1\xeb}\xe3\x8e\xe4{\xdb\xd7\xe2\xd9}=3\x97|\x0c\x1e\xecz\xcc\x92u\x1f'
                b'\xf0\x1d\xbc\x9f\xe4:425155524522'
            ),
            (
                'rfc3739.crt',
                b"@\xde\x1b\xdb\xdc3a\x89:'D\xaf.G' \xb4<\xb3R8\xca;y\x8e\xfb\xef\x14\xbcE\x05F"
                b":1234567890"
            ),
        )

    @data('issuer_serial_info')
    def issuer_serial(self, relative_path, issuer_serial):
        cert = self._load_cert(relative_path)
        self.assertEqual(issuer_serial, cert.issuer_serial)

    @staticmethod
    def authority_key_identifier_info():
        return (
            (
                'keys/test-der.crt',
                b'\xbeB\x85=\xcc\xff\xe3\xf9(\x02\x8f~XV\xb4\xfd\x03\\\xeaK'
            ),
            (
                'keys/test-inter-der.crt',
                b'\xbeB\x85=\xcc\xff\xe3\xf9(\x02\x8f~XV\xb4\xfd\x03\\\xeaK'
            ),
            (
                'keys/test-third-der.crt',
                b'\xd2\n\xfd.%\xd1\xb7!\xd7P~\xbb\xa4}\xbf4\xefR^\x02'
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                b'\xda\xbb.\xaa\xb0\x0c\xb8\x88&Qt\\m\x03\xd3\xc0\xd8\x8fz\xd6'
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                b',\xd5PA\x97\x15\x8b\xf0\x8f6a[J\xfbk\xd9\x99\xc93\x92'
            ),
            (
                'geotrust_certs/codex.crt',
                b'\xde\xcf\\P\xb7\xae\x02\x1f\x15\x17\xaa\x16\xe8\r\xb5(\x9djZ\xf3'
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                b'y\xb4Y\xe6{\xb6\xe5\xe4\x01s\x80\x08\x88\xc8\x1aX\xf6\xe9\x9bn'
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                b'y\xb4Y\xe6{\xb6\xe5\xe4\x01s\x80\x08\x88\xc8\x1aX\xf6\xe9\x9bn'
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                b'd|\\\xe1\xe0`8NH\x9f\x05\xbcUc~?\xaeM\xf7\x1e'
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                b"'\xf8/\xe9]\xd7\r\xf4\xa8\xea\x87\x99=\xfd\x8e\xb3\x9e@\xd0\x91"
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                b"'\xf8/\xe9]\xd7\r\xf4\xa8\xea\x87\x99=\xfd\x8e\xb3\x9e@\xd0\x91"
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                b"'\xf8/\xe9]\xd7\r\xf4\xa8\xea\x87\x99=\xfd\x8e\xb3\x9e@\xd0\x91"
            ),
            (
                'rfc3739.crt',
                b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\xfe\xdc\xba\x98"
            ),
        )

    @data('authority_key_identifier_info')
    def authority_key_identifier(self, relative_path, authority_key_identifier):
        cert = self._load_cert(relative_path)
        self.assertEqual(authority_key_identifier, cert.authority_key_identifier)

    @staticmethod
    def authority_issuer_serial_info():
        return (
            (
                'keys/test-der.crt',
                b'\xdd\x8a\x19x\xae`\x19=\xa7\xf8\x00\xb9\xfbx\xf8\xedu\xb8!\xf8\x8c'
                b'\xdb\x1f\x99\'7w\x93\xb4\xa4\'\xa0:13683582341504654466'
            ),
            (
                'keys/test-inter-der.crt',
                None
            ),
            (
                'keys/test-third-der.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                None
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                None
            ),
            (
                'geotrust_certs/codex.crt',
                None
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                None
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                None
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                None
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                None
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                None
            ),
            (
                'rfc3739.crt',
                None
            ),
        )

    @data('authority_issuer_serial_info')
    def authority_issuer_serial(self, relative_path, authority_issuer_serial):
        cert = self._load_cert(relative_path)
        self.assertEqual(authority_issuer_serial, cert.authority_issuer_serial)

    @staticmethod
    def ocsp_urls_info():
        return (
            (
                'keys/test-der.crt',
                []
            ),
            (
                'keys/test-inter-der.crt',
                []
            ),
            (
                'keys/test-third-der.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                ['http://g2.symcb.com']
            ),
            (
                'geotrust_certs/codex.crt',
                ['http://gm.symcd.com']
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                []
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                ['http://ocsp.root-x1.letsencrypt.org/']
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                ['http://ocsp.root-x1.letsencrypt.org/']
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                []
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                []
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                ['http://ocsp.exampleovca.com/']
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                ['http://ocsp.exampleovca.com/']
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                ['http://ocsp.exampleovca.com/']
            ),
            (
                'rfc3739.crt',
                []
            ),
        )

    @data('ocsp_urls_info')
    def ocsp_urls(self, relative_path, ocsp_url):
        cert = self._load_cert(relative_path)
        self.assertEqual(ocsp_url, cert.ocsp_urls)

    @staticmethod
    def crl_distribution_points_info():
        return (
            (
                'keys/test-der.crt',
                []
            ),
            (
                'keys/test-inter-der.crt',
                []
            ),
            (
                'keys/test-third-der.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://g1.symcb.com/GeoTrustPCA.crl']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'geotrust_certs/codex.crt',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://gm.symcb.com/gm.crl']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                []
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://crl.root-x1.letsencrypt.org']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://crl.root-x1.letsencrypt.org']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://crl.globalsign.com/gs/trustrootcatg2.crl']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                [
                    util.OrderedDict([
                        ('distribution_point', ['http://crl.globalsign.com/gs/trustrootcatg2.crl']),
                        ('reasons', None),
                        ('crl_issuer', None)
                    ])
                ]
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                []
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                []
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                []
            ),
            (
                'rfc3739.crt',
                []
            ),
        )

    @data('crl_distribution_points_info')
    def crl_distribution_points(self, relative_path, crl_distribution_point):
        cert = self._load_cert(relative_path)
        points = [point.native for point in cert.crl_distribution_points]
        self.assertEqual(crl_distribution_point, points)

    @staticmethod
    def valid_domains_info():
        return (
            (
                'keys/test-der.crt',
                []
            ),
            (
                'keys/test-inter-der.crt',
                []
            ),
            (
                'keys/test-third-der.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                []
            ),
            (
                'geotrust_certs/codex.crt',
                ['dev.codexns.io', 'rc.codexns.io', 'packagecontrol.io', 'wbond.net', 'codexns.io']
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                []
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                []
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                []
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                []
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                []
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                ['anything.example.com']
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                ['anything.example.com']
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                ['*.google.com']
            ),
            (
                'rfc3739.crt',
                []
            ),
        )

    @data('valid_domains_info')
    def valid_domains(self, relative_path, valid_domains):
        cert = self._load_cert(relative_path)
        self.assertEqual(valid_domains, cert.valid_domains)

    @staticmethod
    def valid_ips_info():
        return (
            (
                'keys/test-der.crt',
                []
            ),
            (
                'keys/test-inter-der.crt',
                []
            ),
            (
                'keys/test-third-der.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                []
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                []
            ),
            (
                'geotrust_certs/codex.crt',
                []
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                []
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                []
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                []
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                []
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                []
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                []
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                []
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                []
            ),
            (
                'rfc3739.crt',
                []
            ),
        )

    @data('valid_ips_info')
    def valid_ips(self, relative_path, crl_url):
        cert = self._load_cert(relative_path)
        self.assertEqual(crl_url, cert.valid_ips)

    @staticmethod
    def self_issued_info():
        return (
            (
                'keys/test-der.crt',
                True
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
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                True
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                True
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                False
            ),
            (
                'geotrust_certs/codex.crt',
                False
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                True
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                False
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                False
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                False
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                True
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                False
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                False
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                False
            ),
            (
                'rfc3739.crt',
                False
            ),
        )

    @data('self_issued_info')
    def self_issued(self, relative_path, self_issued):
        cert = self._load_cert(relative_path)
        self.assertEqual(self_issued, cert.self_issued)

    @staticmethod
    def self_signed_info():
        return (
            (
                'keys/test-der.crt',
                'maybe'
            ),
            (
                'keys/test-inter-der.crt',
                'no'
            ),
            (
                'keys/test-third-der.crt',
                'no'
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
                'maybe'
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
                'maybe'
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
                'no'
            ),
            (
                'geotrust_certs/codex.crt',
                'no'
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
                'maybe'
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
                'no'
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
                'no'
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
                'no'
            ),
            (
                'globalsign_example_keys/rootCA.cer',
                'maybe'
            ),
            (
                'globalsign_example_keys/SSL1.cer',
                'no'
            ),
            (
                'globalsign_example_keys/SSL2.cer',
                'no'
            ),
            (
                'globalsign_example_keys/SSL3.cer',
                'no'
            ),
            (
                'rfc3739.crt',
                'no'
            ),
        )

    @data('self_signed_info')
    def self_signed(self, relative_path, self_signed):
        cert = self._load_cert(relative_path)
        self.assertEqual(self_signed, cert.self_signed)

    @staticmethod
    def cert_list():
        return (
            (
                'keys/test-der.crt',
            ),
            (
                'keys/test-inter-der.crt',
            ),
            (
                'keys/test-third-der.crt',
            ),
            (
                'geotrust_certs/GeoTrust_Universal_CA.crt',
            ),
            (
                'geotrust_certs/GeoTrust_Primary_CA.crt',
            ),
            (
                'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt',
            ),
            (
                'geotrust_certs/codex.crt',
            ),
            (
                'lets_encrypt/isrgrootx1.pem',
            ),
            (
                'lets_encrypt/letsencryptauthorityx1.pem',
            ),
            (
                'lets_encrypt/letsencryptauthorityx2.pem',
            ),
            (
                'globalsign_example_keys/IssuingCA-der.cer',
            ),
            (
                'globalsign_example_keys/rootCA.cer',
            ),
            (
                'globalsign_example_keys/SSL1.cer',
            ),
            (
                'globalsign_example_keys/SSL2.cer',
            ),
            (
                'globalsign_example_keys/SSL3.cer',
            ),
        )

    @data('cert_list')
    def name_is_rdn_squence_of_single_child_sets(self, relative_path):
        cert = self._load_cert(relative_path)
        for child in cert.subject.chosen:
            self.assertEqual(1, len(child))

    def test_parse_certificate(self):
        cert = self._load_cert('keys/test-der.crt')

        tbs_certificate = cert['tbs_certificate']
        signature = tbs_certificate['signature']
        issuer = tbs_certificate['issuer']
        validity = tbs_certificate['validity']
        subject = tbs_certificate['subject']
        subject_public_key_info = tbs_certificate['subject_public_key_info']
        subject_public_key_algorithm = subject_public_key_info['algorithm']
        subject_public_key = subject_public_key_info['public_key'].parsed
        extensions = tbs_certificate['extensions']

        self.assertEqual(
            'v3',
            tbs_certificate['version'].native
        )
        self.assertEqual(
            13683582341504654466,
            tbs_certificate['serial_number'].native
        )
        self.assertEqual(
            'sha256_rsa',
            signature['algorithm'].native
        )
        self.assertEqual(
            None,
            signature['parameters'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            issuer.native
        )
        self.assertEqual(
            datetime(2015, 5, 6, 14, 37, 16, tzinfo=util.timezone.utc),
            validity['not_before'].native
        )
        self.assertEqual(
            datetime(2025, 5, 3, 14, 37, 16, tzinfo=util.timezone.utc),
            validity['not_after'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            subject.native
        )
        self.assertEqual(
            'rsa',
            subject_public_key_algorithm['algorithm'].native
        )
        self.assertEqual(
            None,
            subject_public_key_algorithm['parameters'].native
        )
        self.assertEqual(
            23903990516906431865559598284199534387004799030432486061102966678620221767754702651554142956492614440585611990224871381291841413369032752409360196079700921141819811294444393525264295297988924243231844876926173670633422654261873814968313363171188082579071492839040415373948505938897419917635370450127498164824808630475648771544810334682447182123219422360569466851807131368135806769502898151721274383486320505905826683946456552230958810028663378886363555981449715929872558073101554364803925363048965464124465016494920967179276744892632783712377912841537032383450409486298694116013299423220523450956288827030007092359007,  # noqa
            subject_public_key['modulus'].native
        )
        self.assertEqual(
            65537,
            subject_public_key['public_exponent'].native
        )
        self.assertEqual(
            None,
            tbs_certificate['issuer_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['issuer_unique_id'],
            core.Void
        )
        self.assertEqual(
            None,
            tbs_certificate['subject_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['subject_unique_id'],
            core.Void
        )

        self.maxDiff = None
        for extension in extensions:
            self.assertIsInstance(
                extension,
                x509.Extension
            )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('extn_id', 'key_identifier'),
                    ('critical', False),
                    ('extn_value', b'\xBE\x42\x85\x3D\xCC\xFF\xE3\xF9\x28\x02\x8F\x7E\x58\x56\xB4\xFD\x03\x5C\xEA\x4B'),
                ]),
                util.OrderedDict([
                    ('extn_id', 'authority_key_identifier'),
                    ('critical', False),
                    (
                        'extn_value',
                        util.OrderedDict([
                            (
                                'key_identifier',
                                b'\xBE\x42\x85\x3D\xCC\xFF\xE3\xF9\x28\x02\x8F\x7E\x58\x56\xB4\xFD\x03\x5C\xEA\x4B'
                            ),
                            (
                                'authority_cert_issuer',
                                [
                                    util.OrderedDict([
                                        ('country_name', 'US'),
                                        ('state_or_province_name', 'Massachusetts'),
                                        ('locality_name', 'Newbury'),
                                        ('organization_name', 'Codex Non Sufficit LC'),
                                        ('organizational_unit_name', 'Testing'),
                                        ('common_name', 'Will Bond'),
                                        ('email_address', 'will@codexns.io'),
                                    ])
                                ]
                            ),
                            ('authority_cert_serial_number', 13683582341504654466),
                        ])
                    ),
                ]),
                util.OrderedDict([
                    ('extn_id', 'basic_constraints'),
                    ('critical', False),
                    (
                        'extn_value',
                        util.OrderedDict([
                            ('ca', True),
                            ('path_len_constraint', None)
                        ])
                    ),
                ]),
            ],
            extensions.native
        )

    def test_parse_dsa_certificate(self):
        cert = self._load_cert('keys/test-dsa-der.crt')

        tbs_certificate = cert['tbs_certificate']
        signature = tbs_certificate['signature']
        issuer = tbs_certificate['issuer']
        validity = tbs_certificate['validity']
        subject = tbs_certificate['subject']
        subject_public_key_info = tbs_certificate['subject_public_key_info']
        subject_public_key_algorithm = subject_public_key_info['algorithm']
        subject_public_key = subject_public_key_info['public_key'].parsed
        extensions = tbs_certificate['extensions']

        self.assertEqual(
            'v3',
            tbs_certificate['version'].native
        )
        self.assertEqual(
            14308214745771946523,
            tbs_certificate['serial_number'].native
        )
        self.assertEqual(
            'sha256_dsa',
            signature['algorithm'].native
        )
        self.assertEqual(
            None,
            signature['parameters'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            issuer.native
        )
        self.assertEqual(
            datetime(2015, 5, 20, 13, 9, 2, tzinfo=util.timezone.utc),
            validity['not_before'].native
        )
        self.assertEqual(
            datetime(2025, 5, 17, 13, 9, 2, tzinfo=util.timezone.utc),
            validity['not_after'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            subject.native
        )
        self.assertEqual(
            'dsa',
            subject_public_key_algorithm['algorithm'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('p', 4511743893397705393934377497936985478231822206263141826261443300639402520800626925517264115785551703273809312112372693877437137848393530691841757974971843334497076835630893064661599193178307024379015589119302113551197423138934242435710226975119594589912289060014025377813473273600967729027125618396732574594753039493158066887433778053086408525146692226448554390096911703556213619406958876388642882534250747780313634767409586007581976273681005928967585750017105562145167146445061803488570714706090280814293902464230717946651489964409785146803791743658888866280873858000476717727810363942159874283767926511678640730707887895260274767195555813448140889391762755466967436731106514029224490921857229134393798015954890071206959203407845438863870686180087606429828973298318856683615900474921310376145478859687052812749087809700610549251964102790514588562086548577933609968589710807989944739877028770343142449461177732058649962678857),  # noqa
                ('q', 71587850165936478337655415373676526523562874562337607790945426056266440596923),
                ('g', 761437146067908309288345767887973163494473925243194806582679580640442238588269326525839153095505341738937595419375068472941615006110237832663093084973431440436421580371384720052414080562019831325744042316268714195397974084616335082272743706567701546951285088540646372701485690904535540223121118329044403681933304838754517522024738251994717369464179515923093116622352823578284891812676662979104509631349201801577889230316128523885862472086364717411346341249139971907827526291913249445756671582283459372536334490171231311487207683108274785825764378203622999309355578169139646003751751448501475767709869676880946562283552431757983801739671783678927397420797147373441051876558068212062253171347849380506793433921881336652424898488378657239798694995315456959568806256079056461448199493507273882763491729787817044805150879660784158902456811649964987582162907020243296662602990514615480712948126671999033658064244112238138589732202),  # noqa
            ]),
            subject_public_key_algorithm['parameters'].native
        )
        self.assertEqual(
            934231235067929794039535952071098031636053793876274937162425423023735221571983693370780054696865229184537343792766496068557051933738826401423094028670222490622041397241325320965905259541032379046252395145258594355589801644789631904099105867133976990593761395721476198083091062806327384261369876465927159169400428623265291958463077792777155465482611741502621885386691681062128487785344975981628995609792181581218570320181053055516069553767918513262908069925035292416868414952256645902605335068760774106734518308281769128146479819566784704033671969858507248124850451414380441279385481154336362988505436125981975735568289420374790767927084033441728922597082155884801013899630856890463962357814273014111039522903328923758417820349377075487103441305806369234738881875734407495707878637895190993370257589211331043479113328811265005530361001980539377903738453549980082795009589559114091215518866106998956304437954236070776810740036,  # noqa
            subject_public_key.native
        )
        self.assertEqual(
            None,
            tbs_certificate['issuer_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['issuer_unique_id'],
            core.Void
        )
        self.assertEqual(
            None,
            tbs_certificate['subject_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['subject_unique_id'],
            core.Void
        )

        self.maxDiff = None
        for extension in extensions:
            self.assertIsInstance(
                extension,
                x509.Extension
            )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('extn_id', 'key_identifier'),
                    ('critical', False),
                    ('extn_value', b'\x81\xA3\x37\x86\xF9\x99\x28\xF2\x74\x70\x60\x87\xF2\xD3\x7E\x8D\x19\x61\xA8\xBE'),
                ]),
                util.OrderedDict([
                    ('extn_id', 'authority_key_identifier'),
                    ('critical', False),
                    (
                        'extn_value',
                        util.OrderedDict([
                            (
                                'key_identifier',
                                b'\x81\xA3\x37\x86\xF9\x99\x28\xF2\x74\x70\x60\x87\xF2\xD3\x7E\x8D\x19\x61\xA8\xBE'
                            ),
                            ('authority_cert_issuer', None),
                            ('authority_cert_serial_number', None),
                        ])
                    ),
                ]),
                util.OrderedDict([
                    ('extn_id', 'basic_constraints'),
                    ('critical', False),
                    (
                        'extn_value',
                        util.OrderedDict([
                            ('ca', True),
                            ('path_len_constraint', None)
                        ])
                    ),
                ]),
            ],
            extensions.native
        )

    def test_parse_dsa_certificate_inheritance(self):
        cert = self._load_cert('DSAParametersInheritedCACert.crt')

        tbs_certificate = cert['tbs_certificate']
        signature = tbs_certificate['signature']
        issuer = tbs_certificate['issuer']
        validity = tbs_certificate['validity']
        subject = tbs_certificate['subject']
        subject_public_key_info = tbs_certificate['subject_public_key_info']
        subject_public_key_algorithm = subject_public_key_info['algorithm']

        self.assertEqual(
            'v3',
            tbs_certificate['version'].native
        )
        self.assertEqual(
            2,
            tbs_certificate['serial_number'].native
        )
        self.assertEqual(
            'sha1_dsa',
            signature['algorithm'].native
        )
        self.assertEqual(
            None,
            signature['parameters'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('organization_name', 'Test Certificates 2011'),
                ('common_name', 'DSA CA'),
            ]),
            issuer.native
        )
        self.assertEqual(
            datetime(2010, 1, 1, 8, 30, tzinfo=util.timezone.utc),
            validity['not_before'].native
        )
        self.assertEqual(
            datetime(2030, 12, 31, 8, 30, tzinfo=util.timezone.utc),
            validity['not_after'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('organization_name', 'Test Certificates 2011'),
                ('common_name', 'DSA Parameters Inherited CA'),
            ]),
            subject.native
        )
        self.assertEqual(
            'dsa',
            subject_public_key_algorithm['algorithm'].native
        )
        self.assertEqual(
            None,
            subject_public_key_algorithm['parameters'].native
        )
        self.assertEqual(
            'dsa',
            subject_public_key_info.algorithm
        )
        self.assertEqual(
            None,
            subject_public_key_info.hash_algo
        )

    def test_parse_ec_certificate(self):
        cert = self._load_cert('keys/test-ec-der.crt')

        tbs_certificate = cert['tbs_certificate']
        signature = tbs_certificate['signature']
        issuer = tbs_certificate['issuer']
        validity = tbs_certificate['validity']
        subject = tbs_certificate['subject']
        subject_public_key_info = tbs_certificate['subject_public_key_info']
        subject_public_key_algorithm = subject_public_key_info['algorithm']
        public_key_params = subject_public_key_info['algorithm']['parameters'].chosen
        field_id = public_key_params['field_id']
        curve = public_key_params['curve']
        subject_public_key = subject_public_key_info['public_key']
        extensions = tbs_certificate['extensions']

        self.assertEqual(
            'v3',
            tbs_certificate['version'].native
        )
        self.assertEqual(
            15854128451240978884,
            tbs_certificate['serial_number'].native
        )
        self.assertEqual(
            'sha256_ecdsa',
            signature['algorithm'].native
        )
        self.assertEqual(
            None,
            signature['parameters'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            issuer.native
        )
        self.assertEqual(
            datetime(2015, 5, 20, 12, 56, 46, tzinfo=util.timezone.utc),
            validity['not_before'].native
        )
        self.assertEqual(
            datetime(2025, 5, 17, 12, 56, 46, tzinfo=util.timezone.utc),
            validity['not_after'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            subject.native
        )
        self.assertEqual(
            'ec',
            subject_public_key_algorithm['algorithm'].native
        )
        self.assertEqual(
            'ecdpVer1',
            public_key_params['version'].native
        )
        self.assertEqual(
            'prime_field',
            field_id['field_type'].native
        )
        self.assertEqual(
            115792089210356248762697446949407573530086143415290314195533631308867097853951,
            field_id['parameters'].native
        )
        self.assertEqual(
            b'\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC',
            curve['a'].native
        )
        self.assertEqual(
            b'\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC'
            b'\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B',
            curve['b'].native
        )
        self.assertEqual(
            b'\xC4\x9D\x36\x08\x86\xE7\x04\x93\x6A\x66\x78\xE1\x13\x9D\x26\xB7\x81\x9F\x7E\x90',
            curve['seed'].native
        )
        self.assertEqual(
            b'\x04\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40'
            b'\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2'
            b'\x96\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E'
            b'\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5',
            public_key_params['base'].native
        )
        self.assertEqual(
            115792089210356248762697446949407573529996955224135760342422259061068512044369,
            public_key_params['order'].native
        )
        self.assertEqual(
            1,
            public_key_params['cofactor'].native
        )
        self.assertEqual(
            None,
            public_key_params['hash'].native
        )
        self.assertEqual(
            b'\x04\x8b]Lq\xf7\xd6\xc6\xa3IcB\\G\x9f\xcbs$\x1d\xc9\xdd\xd1-\xf1:\x9f'
            b'\xb7\x04\xde \xd0X\x00\x93T\xf6\x89\xc7/\x87+\xf7\xf9=;4\xed\x9e{\x0e'
            b'=WB\xdfx\x03\x0b\xcc1\xc6\x03\xd7\x9f`\x01',
            subject_public_key.native
        )
        self.assertEqual(
            (
                63036330335395236932063564494857090016633168203412940864166337576590847793152,
                66640105439272245186116058015235631147470323594355535909132387303736913911809
            ),
            subject_public_key.to_coords()
        )
        self.assertEqual(
            None,
            tbs_certificate['issuer_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['issuer_unique_id'],
            core.Void
        )
        self.assertEqual(
            None,
            tbs_certificate['subject_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['subject_unique_id'],
            core.Void
        )

        self.maxDiff = None
        for extension in extensions:
            self.assertIsInstance(
                extension,
                x509.Extension
            )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('extn_id', 'key_identifier'),
                    ('critical', False),
                    ('extn_value', b'\x54\xAA\x54\x70\x6C\x34\x1A\x6D\xEB\x5D\x97\xD7\x1E\xFC\xD5\x24\x3C\x8A\x0E\xD7'),
                ]),
                util.OrderedDict([
                    ('extn_id', 'authority_key_identifier'),
                    ('critical', False),
                    (
                        'extn_value',
                        util.OrderedDict([
                            (
                                'key_identifier',
                                b'\x54\xAA\x54\x70\x6C\x34\x1A\x6D\xEB\x5D\x97\xD7\x1E\xFC\xD5\x24\x3C\x8A\x0E\xD7'
                            ),
                            ('authority_cert_issuer', None),
                            ('authority_cert_serial_number', None),
                        ])
                    ),
                ]),
                util.OrderedDict([
                    ('extn_id', 'basic_constraints'),
                    ('critical', False),
                    (
                        'extn_value',
                        util.OrderedDict([
                            ('ca', True),
                            ('path_len_constraint', None)
                        ])
                    ),
                ]),
            ],
            extensions.native
        )

    def test_repeated_subject_fields(self):
        cert = self._load_cert('self-signed-repeated-subject-fields.der')
        self.assertEqual(
            cert.subject.native,
            util.OrderedDict([
                ('country_name', 'RU'),
                ('state_or_province_name', 'Some'),
                ('locality_name', 'Any'),
                ('organization_name', 'Org'),
                ('organizational_unit_name', 'OrgUnit'),
                ('common_name', 'zzz.yyy.domain.tld'),
                ('email_address', 'no@email'),
                ('domain_component', ['zzz', 'yyy', 'domain', 'tld'])
            ])
        )

    def test_trusted_certificate(self):
        with open(os.path.join(fixtures_dir, 'sender_dummycorp.com.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            trusted_cert = x509.TrustedCertificate.load(cert_bytes)

        cert = trusted_cert[0]
        aux = trusted_cert[1]

        self.assertEqual(
            cert.subject.native,
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'VA'),
                ('locality_name', 'Herndon'),
                ('organization_name', 'Internet Gadgets Pty Ltd'),
                ('common_name', 'Fake Sender'),
                ('email_address', 'sender@dummycorp.com'),
            ])
        )

        self.assertEqual(
            aux['trust'].native,
            ['email_protection']
        )

        self.assertEqual(
            aux['reject'].native,
            ['client_auth', 'server_auth']
        )

    def test_iri_with_port(self):
        with open(os.path.join(fixtures_dir, 'admin.ch.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)

        self.assertEqual(
            [dp.native for dp in cert.crl_distribution_points],
            [
                util.OrderedDict([
                    ('distribution_point', ['http://www.pki.admin.ch/crl/SSLCA01.crl']),
                    ('reasons', None),
                    ('crl_issuer', None)
                ]),
                util.OrderedDict([
                    (
                        'distribution_point',
                        [
                            'ldap://admindir.admin.ch:389/'
                            'cn=Swiss Government SSL CA 01,'
                            'ou=Certification Authorities,'
                            'ou=Services,'
                            'o=Admin,'
                            'c=CH'
                        ]
                    ),
                    ('reasons', None),
                    ('crl_issuer', None)
                ])
            ]
        )

    def test_extended_datetime(self):
        cert = self._load_cert('9999-years-rsa-cert.pem')
        self.assertEqual(
            cert['tbs_certificate']['validity']['not_before'].native,
            util.extended_datetime(0, 1, 1, 0, 0, 1, tzinfo=util.timezone.utc)
        )

    def test_teletex_that_is_really_latin1(self):
        self.assertEqual(
            '{}',
            x509.DirectoryString.load(b'\x14\x02{}').native
        )

    def test_strict_teletex(self):
        with x509.strict_teletex():
            with self.assertRaises(UnicodeDecodeError):
                self.assertEqual(
                    '{}',
                    x509.DirectoryString.load(b'\x14\x02{}').native
                )

        # Make sure outside of the contextmanager we are back to
        # liberal interpretation of TeletexString
        self.assertEqual(
            '{}',
            x509.DirectoryString.load(b'\x14\x02{}').native
        )

    def test_validity_after_before(self):
        cert = self._load_cert("keys/test-validity.crt")

        self.assertEqual(cert.not_valid_after, datetime(2118, 1, 28, 12, 27, 39, tzinfo=util.timezone.utc))
        self.assertEqual(cert.not_valid_before, datetime(2018, 2, 21, 12, 27, 39, tzinfo=util.timezone.utc))

    def test_invalid_email_encoding(self):
        cert = self._load_cert("invalid_email_tag.pem")
        self.assertEqual('info@keyweb.de', cert.subject.native['email_address'])
