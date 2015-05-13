# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import datetime
import ipaddress
from email.utils import parseaddr

import idna

import six

from six.moves import urllib_parse

from cryptography import utils, x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes


def _obj2txt(backend, obj):
    # Set to 80 on the recommendation of
    # https://www.openssl.org/docs/crypto/OBJ_nid2ln.html#return_values
    buf_len = 80
    buf = backend._ffi.new("char[]", buf_len)
    res = backend._lib.OBJ_obj2txt(buf, buf_len, obj, 1)
    assert res > 0
    return backend._ffi.buffer(buf, res)[:].decode()


def _asn1_integer_to_int(backend, asn1_int):
    bn = backend._lib.ASN1_INTEGER_to_BN(asn1_int, backend._ffi.NULL)
    assert bn != backend._ffi.NULL
    bn = backend._ffi.gc(bn, backend._lib.BN_free)
    return backend._bn_to_int(bn)


def _asn1_string_to_utf8(backend, asn1_string):
    buf = backend._ffi.new("unsigned char **")
    res = backend._lib.ASN1_STRING_to_UTF8(buf, asn1_string)
    assert res >= 0
    assert buf[0] != backend._ffi.NULL
    buf = backend._ffi.gc(
        buf, lambda buffer: backend._lib.OPENSSL_free(buffer[0])
    )
    return backend._ffi.buffer(buf[0], res)[:].decode('utf8')


def _build_x509_name_entry(backend, x509_name_entry):
    obj = backend._lib.X509_NAME_ENTRY_get_object(x509_name_entry)
    assert obj != backend._ffi.NULL
    data = backend._lib.X509_NAME_ENTRY_get_data(x509_name_entry)
    assert data != backend._ffi.NULL
    value = _asn1_string_to_utf8(backend, data)
    oid = _obj2txt(backend, obj)

    return x509.NameAttribute(x509.ObjectIdentifier(oid), value)


def _build_x509_name(backend, x509_name):
    count = backend._lib.X509_NAME_entry_count(x509_name)
    attributes = []
    for x in range(count):
        entry = backend._lib.X509_NAME_get_entry(x509_name, x)
        attributes.append(_build_x509_name_entry(backend, entry))

    return x509.Name(attributes)


def _build_general_names(backend, gns):
    num = backend._lib.sk_GENERAL_NAME_num(gns)
    names = []
    for i in range(num):
        gn = backend._lib.sk_GENERAL_NAME_value(gns, i)
        assert gn != backend._ffi.NULL
        names.append(_build_general_name(backend, gn))

    return names


def _build_general_name(backend, gn):
    if gn.type == backend._lib.GEN_DNS:
        data = backend._ffi.buffer(gn.d.dNSName.data, gn.d.dNSName.length)[:]
        return x509.DNSName(idna.decode(data))
    elif gn.type == backend._lib.GEN_URI:
        data = backend._ffi.buffer(
            gn.d.uniformResourceIdentifier.data,
            gn.d.uniformResourceIdentifier.length
        )[:].decode("ascii")
        parsed = urllib_parse.urlparse(data)
        hostname = idna.decode(parsed.hostname)
        if parsed.port:
            netloc = hostname + u":" + six.text_type(parsed.port)
        else:
            netloc = hostname

        # Note that building a URL in this fashion means it should be
        # semantically indistinguishable from the original but is not
        # guaranteed to be exactly the same.
        uri = urllib_parse.urlunparse((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        return x509.UniformResourceIdentifier(uri)
    elif gn.type == backend._lib.GEN_RID:
        oid = _obj2txt(backend, gn.d.registeredID)
        return x509.RegisteredID(x509.ObjectIdentifier(oid))
    elif gn.type == backend._lib.GEN_IPADD:
        return x509.IPAddress(
            ipaddress.ip_address(
                backend._ffi.buffer(
                    gn.d.iPAddress.data, gn.d.iPAddress.length
                )[:]
            )
        )
    elif gn.type == backend._lib.GEN_DIRNAME:
        return x509.DirectoryName(
            _build_x509_name(backend, gn.d.directoryName)
        )
    elif gn.type == backend._lib.GEN_EMAIL:
        data = backend._ffi.buffer(
            gn.d.rfc822Name.data, gn.d.rfc822Name.length
        )[:].decode("ascii")
        name, address = parseaddr(data)
        parts = address.split(u"@")
        if name or len(parts) > 2 or not address:
            # parseaddr has found a name (e.g. Name <email>) or the split
            # has found more than 2 parts (which means more than one @ sign)
            # or the entire value is an empty string.
            raise ValueError("Invalid rfc822name value")
        elif len(parts) == 1:
            # Single label email name. This is valid for local delivery. No
            # IDNA decoding can be done since there is no domain component.
            return x509.RFC822Name(address)
        else:
            # A normal email of the form user@domain.com. Let's attempt to
            # decode the domain component and return the entire address.
            return x509.RFC822Name(
                parts[0] + u"@" + idna.decode(parts[1])
            )
    else:
        # otherName, x400Address or ediPartyName
        raise x509.UnsupportedGeneralNameType(
            "{0} is not a supported type".format(
                x509._GENERAL_NAMES.get(gn.type, gn.type)
            ),
            gn.type
        )


@utils.register_interface(x509.Certificate)
class _Certificate(object):
    def __init__(self, backend, x509):
        self._backend = backend
        self._x509 = x509

    def __eq__(self, other):
        if not isinstance(other, x509.Certificate):
            return NotImplemented

        res = self._backend._lib.X509_cmp(self._x509, other._x509)
        return res == 0

    def __ne__(self, other):
        return not self == other

    def fingerprint(self, algorithm):
        h = hashes.Hash(algorithm, self._backend)
        bio = self._backend._create_mem_bio()
        res = self._backend._lib.i2d_X509_bio(
            bio, self._x509
        )
        assert res == 1
        der = self._backend._read_mem_bio(bio)
        h.update(der)
        return h.finalize()

    @property
    def version(self):
        version = self._backend._lib.X509_get_version(self._x509)
        if version == 0:
            return x509.Version.v1
        elif version == 2:
            return x509.Version.v3
        else:
            raise x509.InvalidVersion(
                "{0} is not a valid X509 version".format(version), version
            )

    @property
    def serial(self):
        asn1_int = self._backend._lib.X509_get_serialNumber(self._x509)
        assert asn1_int != self._backend._ffi.NULL
        return _asn1_integer_to_int(self._backend, asn1_int)

    def public_key(self):
        pkey = self._backend._lib.X509_get_pubkey(self._x509)
        assert pkey != self._backend._ffi.NULL
        pkey = self._backend._ffi.gc(pkey, self._backend._lib.EVP_PKEY_free)

        return self._backend._evp_pkey_to_public_key(pkey)

    @property
    def not_valid_before(self):
        asn1_time = self._backend._lib.X509_get_notBefore(self._x509)
        return self._parse_asn1_time(asn1_time)

    @property
    def not_valid_after(self):
        asn1_time = self._backend._lib.X509_get_notAfter(self._x509)
        return self._parse_asn1_time(asn1_time)

    def _parse_asn1_time(self, asn1_time):
        assert asn1_time != self._backend._ffi.NULL
        generalized_time = self._backend._lib.ASN1_TIME_to_generalizedtime(
            asn1_time, self._backend._ffi.NULL
        )
        assert generalized_time != self._backend._ffi.NULL
        generalized_time = self._backend._ffi.gc(
            generalized_time, self._backend._lib.ASN1_GENERALIZEDTIME_free
        )
        time = self._backend._ffi.string(
            self._backend._lib.ASN1_STRING_data(
                self._backend._ffi.cast("ASN1_STRING *", generalized_time)
            )
        ).decode("ascii")
        return datetime.datetime.strptime(time, "%Y%m%d%H%M%SZ")

    @property
    def issuer(self):
        issuer = self._backend._lib.X509_get_issuer_name(self._x509)
        assert issuer != self._backend._ffi.NULL
        return _build_x509_name(self._backend, issuer)

    @property
    def subject(self):
        subject = self._backend._lib.X509_get_subject_name(self._x509)
        assert subject != self._backend._ffi.NULL
        return _build_x509_name(self._backend, subject)

    @property
    def signature_hash_algorithm(self):
        oid = _obj2txt(self._backend, self._x509.sig_alg.algorithm)
        try:
            return x509._SIG_OIDS_TO_HASH[oid]
        except KeyError:
            raise UnsupportedAlgorithm(
                "Signature algorithm OID:{0} not recognized".format(oid)
            )

    @property
    def extensions(self):
        extensions = []
        seen_oids = set()
        extcount = self._backend._lib.X509_get_ext_count(self._x509)
        for i in range(0, extcount):
            ext = self._backend._lib.X509_get_ext(self._x509, i)
            assert ext != self._backend._ffi.NULL
            crit = self._backend._lib.X509_EXTENSION_get_critical(ext)
            critical = crit == 1
            oid = x509.ObjectIdentifier(_obj2txt(self._backend, ext.object))
            if oid in seen_oids:
                raise x509.DuplicateExtension(
                    "Duplicate {0} extension found".format(oid), oid
                )
            elif oid == x509.OID_BASIC_CONSTRAINTS:
                value = self._build_basic_constraints(ext)
            elif oid == x509.OID_SUBJECT_KEY_IDENTIFIER:
                value = self._build_subject_key_identifier(ext)
            elif oid == x509.OID_KEY_USAGE:
                value = self._build_key_usage(ext)
            elif oid == x509.OID_SUBJECT_ALTERNATIVE_NAME:
                value = self._build_subject_alt_name(ext)
            elif oid == x509.OID_EXTENDED_KEY_USAGE:
                value = self._build_extended_key_usage(ext)
            elif oid == x509.OID_AUTHORITY_KEY_IDENTIFIER:
                value = self._build_authority_key_identifier(ext)
            elif oid == x509.OID_AUTHORITY_INFORMATION_ACCESS:
                value = self._build_authority_information_access(ext)
            elif oid == x509.OID_CERTIFICATE_POLICIES:
                value = self._build_certificate_policies(ext)
            elif oid == x509.OID_CRL_DISTRIBUTION_POINTS:
                value = self._build_crl_distribution_points(ext)
            elif critical:
                raise x509.UnsupportedExtension(
                    "{0} is not currently supported".format(oid), oid
                )
            else:
                # Unsupported non-critical extension, silently skipping for now
                seen_oids.add(oid)
                continue

            seen_oids.add(oid)
            extensions.append(x509.Extension(oid, critical, value))

        return x509.Extensions(extensions)

    def _build_certificate_policies(self, ext):
        cp = self._backend._ffi.cast(
            "Cryptography_STACK_OF_POLICYINFO *",
            self._backend._lib.X509V3_EXT_d2i(ext)
        )
        assert cp != self._backend._ffi.NULL
        cp = self._backend._ffi.gc(cp, self._backend._lib.sk_POLICYINFO_free)
        num = self._backend._lib.sk_POLICYINFO_num(cp)
        certificate_policies = []
        for i in range(num):
            qualifiers = None
            pi = self._backend._lib.sk_POLICYINFO_value(cp, i)
            oid = x509.ObjectIdentifier(_obj2txt(self._backend, pi.policyid))
            if pi.qualifiers != self._backend._ffi.NULL:
                qnum = self._backend._lib.sk_POLICYQUALINFO_num(pi.qualifiers)
                qualifiers = []
                for j in range(qnum):
                    pqi = self._backend._lib.sk_POLICYQUALINFO_value(
                        pi.qualifiers, j
                    )
                    pqualid = x509.ObjectIdentifier(
                        _obj2txt(self._backend, pqi.pqualid)
                    )
                    if pqualid == x509.OID_CPS_QUALIFIER:
                        cpsuri = self._backend._ffi.buffer(
                            pqi.d.cpsuri.data, pqi.d.cpsuri.length
                        )[:].decode('ascii')
                        qualifiers.append(cpsuri)
                    elif pqualid == x509.OID_CPS_USER_NOTICE:
                        user_notice = self._build_user_notice(pqi.d.usernotice)
                        qualifiers.append(user_notice)

            certificate_policies.append(
                x509.PolicyInformation(oid, qualifiers)
            )

        return x509.CertificatePolicies(certificate_policies)

    def _build_user_notice(self, un):
        explicit_text = None
        notice_reference = None

        if un.exptext != self._backend._ffi.NULL:
            explicit_text = _asn1_string_to_utf8(self._backend, un.exptext)

        if un.noticeref != self._backend._ffi.NULL:
            organization = _asn1_string_to_utf8(
                self._backend, un.noticeref.organization
            )

            num = self._backend._lib.sk_ASN1_INTEGER_num(
                un.noticeref.noticenos
            )
            notice_numbers = []
            for i in range(num):
                asn1_int = self._backend._lib.sk_ASN1_INTEGER_value(
                    un.noticeref.noticenos, i
                )
                notice_num = _asn1_integer_to_int(
                    self._backend, asn1_int
                )
                notice_numbers.append(notice_num)

            notice_reference = x509.NoticeReference(
                organization, notice_numbers
            )

        return x509.UserNotice(notice_reference, explicit_text)

    def _build_basic_constraints(self, ext):
        bc_st = self._backend._lib.X509V3_EXT_d2i(ext)
        assert bc_st != self._backend._ffi.NULL
        basic_constraints = self._backend._ffi.cast(
            "BASIC_CONSTRAINTS *", bc_st
        )
        basic_constraints = self._backend._ffi.gc(
            basic_constraints, self._backend._lib.BASIC_CONSTRAINTS_free
        )
        # The byte representation of an ASN.1 boolean true is \xff. OpenSSL
        # chooses to just map this to its ordinal value, so true is 255 and
        # false is 0.
        ca = basic_constraints.ca == 255
        if basic_constraints.pathlen == self._backend._ffi.NULL:
            path_length = None
        else:
            path_length = _asn1_integer_to_int(
                self._backend, basic_constraints.pathlen
            )

        return x509.BasicConstraints(ca, path_length)

    def _build_subject_key_identifier(self, ext):
        asn1_string = self._backend._lib.X509V3_EXT_d2i(ext)
        assert asn1_string != self._backend._ffi.NULL
        asn1_string = self._backend._ffi.cast(
            "ASN1_OCTET_STRING *", asn1_string
        )
        asn1_string = self._backend._ffi.gc(
            asn1_string, self._backend._lib.ASN1_OCTET_STRING_free
        )
        return x509.SubjectKeyIdentifier(
            self._backend._ffi.buffer(asn1_string.data, asn1_string.length)[:]
        )

    def _build_authority_key_identifier(self, ext):
        akid = self._backend._lib.X509V3_EXT_d2i(ext)
        assert akid != self._backend._ffi.NULL
        akid = self._backend._ffi.cast("AUTHORITY_KEYID *", akid)
        akid = self._backend._ffi.gc(
            akid, self._backend._lib.AUTHORITY_KEYID_free
        )
        key_identifier = None
        authority_cert_issuer = None
        authority_cert_serial_number = None

        if akid.keyid != self._backend._ffi.NULL:
            key_identifier = self._backend._ffi.buffer(
                akid.keyid.data, akid.keyid.length
            )[:]

        if akid.issuer != self._backend._ffi.NULL:
            authority_cert_issuer = _build_general_names(
                self._backend, akid.issuer
            )

        if akid.serial != self._backend._ffi.NULL:
            authority_cert_serial_number = _asn1_integer_to_int(
                self._backend, akid.serial
            )

        return x509.AuthorityKeyIdentifier(
            key_identifier, authority_cert_issuer, authority_cert_serial_number
        )

    def _build_authority_information_access(self, ext):
        aia = self._backend._lib.X509V3_EXT_d2i(ext)
        assert aia != self._backend._ffi.NULL
        aia = self._backend._ffi.cast(
            "Cryptography_STACK_OF_ACCESS_DESCRIPTION *", aia
        )
        aia = self._backend._ffi.gc(
            aia, self._backend._lib.sk_ACCESS_DESCRIPTION_free
        )
        num = self._backend._lib.sk_ACCESS_DESCRIPTION_num(aia)
        access_descriptions = []
        for i in range(num):
            ad = self._backend._lib.sk_ACCESS_DESCRIPTION_value(aia, i)
            assert ad.method != self._backend._ffi.NULL
            oid = x509.ObjectIdentifier(_obj2txt(self._backend, ad.method))
            assert ad.location != self._backend._ffi.NULL
            gn = _build_general_name(self._backend, ad.location)
            access_descriptions.append(x509.AccessDescription(oid, gn))

        return x509.AuthorityInformationAccess(access_descriptions)

    def _build_key_usage(self, ext):
        bit_string = self._backend._lib.X509V3_EXT_d2i(ext)
        assert bit_string != self._backend._ffi.NULL
        bit_string = self._backend._ffi.cast("ASN1_BIT_STRING *", bit_string)
        bit_string = self._backend._ffi.gc(
            bit_string, self._backend._lib.ASN1_BIT_STRING_free
        )
        get_bit = self._backend._lib.ASN1_BIT_STRING_get_bit
        digital_signature = get_bit(bit_string, 0) == 1
        content_commitment = get_bit(bit_string, 1) == 1
        key_encipherment = get_bit(bit_string, 2) == 1
        data_encipherment = get_bit(bit_string, 3) == 1
        key_agreement = get_bit(bit_string, 4) == 1
        key_cert_sign = get_bit(bit_string, 5) == 1
        crl_sign = get_bit(bit_string, 6) == 1
        encipher_only = get_bit(bit_string, 7) == 1
        decipher_only = get_bit(bit_string, 8) == 1
        return x509.KeyUsage(
            digital_signature,
            content_commitment,
            key_encipherment,
            data_encipherment,
            key_agreement,
            key_cert_sign,
            crl_sign,
            encipher_only,
            decipher_only
        )

    def _build_subject_alt_name(self, ext):
        gns = self._backend._ffi.cast(
            "GENERAL_NAMES *", self._backend._lib.X509V3_EXT_d2i(ext)
        )
        assert gns != self._backend._ffi.NULL
        gns = self._backend._ffi.gc(gns, self._backend._lib.GENERAL_NAMES_free)
        general_names = _build_general_names(self._backend, gns)

        return x509.SubjectAlternativeName(general_names)

    def _build_extended_key_usage(self, ext):
        sk = self._backend._ffi.cast(
            "Cryptography_STACK_OF_ASN1_OBJECT *",
            self._backend._lib.X509V3_EXT_d2i(ext)
        )
        assert sk != self._backend._ffi.NULL
        sk = self._backend._ffi.gc(sk, self._backend._lib.sk_ASN1_OBJECT_free)
        num = self._backend._lib.sk_ASN1_OBJECT_num(sk)
        ekus = []

        for i in range(num):
            obj = self._backend._lib.sk_ASN1_OBJECT_value(sk, i)
            assert obj != self._backend._ffi.NULL
            oid = x509.ObjectIdentifier(_obj2txt(self._backend, obj))
            ekus.append(oid)

        return x509.ExtendedKeyUsage(ekus)

    def _build_crl_distribution_points(self, ext):
        cdps = self._backend._ffi.cast(
            "Cryptography_STACK_OF_DIST_POINT *",
            self._backend._lib.X509V3_EXT_d2i(ext)
        )
        assert cdps != self._backend._ffi.NULL
        cdps = self._backend._ffi.gc(
            cdps, self._backend._lib.sk_DIST_POINT_free)
        num = self._backend._lib.sk_DIST_POINT_num(cdps)

        dist_points = []
        for i in range(num):
            full_name = None
            relative_name = None
            crl_issuer = None
            reasons = None
            cdp = self._backend._lib.sk_DIST_POINT_value(cdps, i)
            if cdp.reasons != self._backend._ffi.NULL:
                # We will check each bit from RFC 5280
                # ReasonFlags ::= BIT STRING {
                #      unused                  (0),
                #      keyCompromise           (1),
                #      cACompromise            (2),
                #      affiliationChanged      (3),
                #      superseded              (4),
                #      cessationOfOperation    (5),
                #      certificateHold         (6),
                #      privilegeWithdrawn      (7),
                #      aACompromise            (8) }
                reasons = []
                get_bit = self._backend._lib.ASN1_BIT_STRING_get_bit
                if get_bit(cdp.reasons, 1):
                    reasons.append(x509.ReasonFlags.key_compromise)

                if get_bit(cdp.reasons, 2):
                    reasons.append(x509.ReasonFlags.ca_compromise)

                if get_bit(cdp.reasons, 3):
                    reasons.append(x509.ReasonFlags.affiliation_changed)

                if get_bit(cdp.reasons, 4):
                    reasons.append(x509.ReasonFlags.superseded)

                if get_bit(cdp.reasons, 5):
                    reasons.append(x509.ReasonFlags.cessation_of_operation)

                if get_bit(cdp.reasons, 6):
                    reasons.append(x509.ReasonFlags.certificate_hold)

                if get_bit(cdp.reasons, 7):
                    reasons.append(x509.ReasonFlags.privilege_withdrawn)

                if get_bit(cdp.reasons, 8):
                    reasons.append(x509.ReasonFlags.aa_compromise)

                reasons = frozenset(reasons)

            if cdp.CRLissuer != self._backend._ffi.NULL:
                crl_issuer = _build_general_names(self._backend, cdp.CRLissuer)

            # Certificates may have a crl_issuer/reasons and no distribution
            # point so make sure it's not null.
            if cdp.distpoint != self._backend._ffi.NULL:
                # Type 0 is fullName, there is no #define for it in the code.
                if cdp.distpoint.type == 0:
                    full_name = _build_general_names(
                        self._backend, cdp.distpoint.name.fullname
                    )
                # OpenSSL code doesn't test for a specific type for
                # relativename, everything that isn't fullname is considered
                # relativename.
                else:
                    rns = cdp.distpoint.name.relativename
                    rnum = self._backend._lib.sk_X509_NAME_ENTRY_num(rns)
                    attributes = []
                    for i in range(rnum):
                        rn = self._backend._lib.sk_X509_NAME_ENTRY_value(
                            rns, i
                        )
                        assert rn != self._backend._ffi.NULL
                        attributes.append(
                            _build_x509_name_entry(self._backend, rn)
                        )

                    relative_name = x509.Name(attributes)

            dist_points.append(
                x509.DistributionPoint(
                    full_name, relative_name, reasons, crl_issuer
                )
            )

        return x509.CRLDistributionPoints(dist_points)


@utils.register_interface(x509.CertificateSigningRequest)
class _CertificateSigningRequest(object):
    def __init__(self, backend, x509_req):
        self._backend = backend
        self._x509_req = x509_req

    def public_key(self):
        pkey = self._backend._lib.X509_REQ_get_pubkey(self._x509_req)
        assert pkey != self._backend._ffi.NULL
        pkey = self._backend._ffi.gc(pkey, self._backend._lib.EVP_PKEY_free)
        return self._backend._evp_pkey_to_public_key(pkey)

    @property
    def subject(self):
        subject = self._backend._lib.X509_REQ_get_subject_name(self._x509_req)
        assert subject != self._backend._ffi.NULL
        return _build_x509_name(self._backend, subject)

    @property
    def signature_hash_algorithm(self):
        oid = _obj2txt(self._backend, self._x509_req.sig_alg.algorithm)
        try:
            return x509._SIG_OIDS_TO_HASH[oid]
        except KeyError:
            raise UnsupportedAlgorithm(
                "Signature algorithm OID:{0} not recognized".format(oid)
            )
