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

import calendar
import datetime
import ipaddress
from email.utils import parseaddr

import idna

import six

from six.moves import urllib_parse

from cryptography import utils, x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization


def _obj2txt(backend, obj):
    # Set to 80 on the recommendation of
    # https://www.openssl.org/docs/crypto/OBJ_nid2ln.html#return_values
    buf_len = 80
    buf = backend._ffi.new("char[]", buf_len)
    res = backend._lib.OBJ_obj2txt(buf, buf_len, obj, 1)
    assert res > 0
    return backend._ffi.buffer(buf, res)[:].decode()


def _build_x509_name(backend, x509_name):
    count = backend._lib.X509_NAME_entry_count(x509_name)
    attributes = []
    for x in range(count):
        entry = backend._lib.X509_NAME_get_entry(x509_name, x)
        obj = backend._lib.X509_NAME_ENTRY_get_object(entry)
        assert obj != backend._ffi.NULL
        data = backend._lib.X509_NAME_ENTRY_get_data(entry)
        assert data != backend._ffi.NULL
        buf = backend._ffi.new("unsigned char **")
        res = backend._lib.ASN1_STRING_to_UTF8(buf, data)
        assert res >= 0
        assert buf[0] != backend._ffi.NULL
        buf = backend._ffi.gc(
            buf, lambda buffer: backend._lib.OPENSSL_free(buffer[0])
        )
        value = backend._ffi.buffer(buf[0], res)[:].decode('utf8')
        oid = _obj2txt(backend, obj)
        attributes.append(
            x509.NameAttribute(
                x509.ObjectIdentifier(oid), value
            )
        )

    return x509.Name(attributes)


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
        bn = self._backend._lib.ASN1_INTEGER_to_BN(
            asn1_int, self._backend._ffi.NULL
        )
        assert bn != self._backend._ffi.NULL
        bn = self._backend._ffi.gc(bn, self._backend._lib.BN_free)
        return self._backend._bn_to_int(bn)

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
            bn = self._backend._lib.ASN1_INTEGER_to_BN(
                basic_constraints.pathlen, self._backend._ffi.NULL
            )
            assert bn != self._backend._ffi.NULL
            bn = self._backend._ffi.gc(bn, self._backend._lib.BN_free)
            path_length = self._backend._bn_to_int(bn)

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
        num = self._backend._lib.sk_GENERAL_NAME_num(gns)
        general_names = []

        for i in range(num):
            gn = self._backend._lib.sk_GENERAL_NAME_value(gns, i)
            assert gn != self._backend._ffi.NULL
            value = _build_general_name(self._backend, gn)

            general_names.append(value)

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


def _make_asn1_int(backend, x):
    i = backend._lib.ASN1_INTEGER_new()
    #i = backend._ffi.gc(i, backend._lib.ASN1_INTEGER_free)
    backend._lib.ASN1_INTEGER_set(i, x)
    return i


def _make_asn1_str(backend, x, n):
    s = backend._lib.ASN1_OCTET_STRING_new()
    #s = backend._ffi.gc(s, backend._lib.ASN1_OCTET_STRING_free)
    backend._lib.ASN1_OCTET_STRING_set(s, x, n)
    return s


def _make_name(backend, attributes):
    resolve = {
        x509.OID_COMMON_NAME: 'CN',
        x509.OID_COUNTRY_NAME: 'C',
        x509.OID_STATE_OR_PROVINCE_NAME: 'ST',
        x509.OID_LOCALITY_NAME: 'L',
        x509.OID_ORGANIZATION_NAME: 'O',
        x509.OID_ORGANIZATIONAL_UNIT_NAME: 'OU',
    }
    subject = backend._lib.X509_NAME_new()
    subject = backend._ffi.gc(subject, backend._lib.X509_NAME_free)
    for attribute in attributes:
        value = attribute.value
        if isinstance(value, unicode):
            value = value.encode('ascii')
        res = backend._lib.X509_NAME_add_entry_by_txt(
            subject,
            resolve[attribute.oid],
            backend._lib.MBSTRING_ASC,
            value,
            -1, -1, 0,
        )
        assert res == 1
    return subject


def _txt2obj(backend, name):
    if isinstance(name, unicode):
        name = name.encode('ascii')
    obj = backend._lib.OBJ_txt2obj(name, 1)
    if obj == backend._ffi.NULL:
        raise ValueError('Unknown ASN.1 object "%s".' % name)
    # NOTE: not sure if we should GC...
    return obj


def _make_basic_constraints(backend, ca=False, pathlen=0):
    obj = _txt2obj(backend, x509.OID_BASIC_CONSTRAINTS.dotted_string)
    assert obj != None
    constraints = backend._lib.BASIC_CONSTRAINTS_new()
    constraints.ca = 255 if ca else 0
    if ca:
        constraints.pathlen = _make_asn1_int(backend, pathlen)

    # Allocate a buffer for encoded payload.
    cdata = backend._ffi.new(
        'unsigned char[]',
        2048,  # TODO: shrink to fit!
    )
    assert cdata != backend._ffi.NULL

    # Fetch the encoded payload.
    p = backend._ffi.new('unsigned char*[1]')
    assert p != backend._ffi.NULL
    p[0] = cdata
    r = backend._lib.i2d_BASIC_CONSTRAINTS(constraints, p)
    assert r > 0

    # Wrap that in an X509 extension object.
    extension = backend._lib.X509_EXTENSION_create_by_OBJ(
        backend._ffi.NULL,
        obj,
        1,
        _make_asn1_str(backend, cdata, r),
    )
    assert extension != backend._ffi.NULL
    return extension


@utils.register_interface(x509.CertificateSigningRequestBuilder)
class _CertificateSigningRequestBuilder(object):
    def __init__(self, backend):
        self._backend = backend
        self._x509_csr = self._backend._lib.X509_REQ_new()
        assert self._x509_csr != self._backend._ffi.NULL
        self._extensions = self._backend._lib.sk_X509_EXTENSION_new_null()
        self._extensions = self._backend._ffi.gc(
            self._extensions,
            self._backend._lib.sk_X509_EXTENSION_free,
        )

    # TODO: accept {v1, v3} enum instead of {0, 2} int?
    def set_version(self, version):
        if version not in (0, 2):
            raise ValueError('Version must be 0 (v1) or 2 (v3).')
        res = self._backend._lib.X509_REQ_set_version(self._x509_csr, version)
        assert res == 1
        return self

    def set_subject_name(self, attributes):
        name = _make_name(self._backend, attributes)
        res = self._backend._lib.X509_REQ_set_subject_name(
            self._x509_csr, name
        )
        assert res == 1
        return self

    def add_extension(self, extension):
        if not isinstance(extension, x509.Extension):
            raise TypeError('Expecting an x509 extension.')

        if isinstance(extension.value, x509.BasicConstraints):
            extension = _make_basic_constraints(
                self._backend,
                extension.value.ca,
                extension.value.path_length
            )
        else:
            raise ValueError('Extension not yet supported.')

        res = self._backend._lib.sk_X509_EXTENSION_push(
            self._extensions, extension
        )
        assert res == 1
        return self

    def sign(self, private_key, algorithm):
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise TypeError('Algorithm must be a registered hash algorithm.')

        evp_md = self._backend._lib.EVP_get_digestbyname(
            algorithm.name.encode('ascii')
        )
        assert evp_md != self._backend._ffi.NULL

        res = self._backend._lib.X509_REQ_add_extensions(
            self._x509_csr, self._extensions
        )
        assert res == 1

        public_key = private_key.public_key()
        res = self._backend._lib.X509_REQ_set_pubkey(
            self._x509_csr, public_key._evp_pkey
        )
        assert res == 1

        res = self._backend._lib.X509_REQ_sign(
            self._x509_csr, private_key._evp_pkey, evp_md
        )
        assert res > 0
        return self

    def public_bytes(self, encoding):
        if not isinstance(encoding, serialization.Encoding):
            raise TypeError("encoding must be an item from the Encoding enum")

        # TODO: make text prelude optional.
        bio = self._backend._create_mem_bio()
        res = self._backend._lib.X509_REQ_print(bio, self._x509_csr)
        assert res == 1
        if encoding is serialization.Encoding.PEM:
            res = self._backend._lib.PEM_write_bio_X509_REQ(
                bio, self._x509_csr
            )
        elif encoding is serialization.Encoding.DER:
            res = self._backend._lib.i2d_X509_REQ_bio(bio, self._x509_csr)
        assert res == 1
        return self._backend._read_mem_bio(bio)


@utils.register_interface(x509.CertificateBuilder)
class _CertificateBuilder(object):
    def __init__(self, backend):
        self._backend = backend
        self._x509 = self._backend._lib.X509_new()
        self._x509 = self._backend._ffi.gc(self._x509, backend._lib.X509_free)

    def set_version(self, version):
        res = self._backend._lib.X509_set_version(self._x509, 2)
        assert res == 1
        return self

    def set_issuer_name(self, attributes):
        res = self._backend._lib.X509_set_issuer_name(
            self._x509, _make_name(self._backend, attributes)
        )
        assert res == 1
        return self

    def set_subject_name(self, attributes):
        res = self._backend._lib.X509_set_subject_name(
            self._x509, _make_name(self._backend, attributes)
        )
        assert res == 1
        return self

    def set_public_key(self, public_key):
        res = self._backend._lib.X509_set_pubkey(
            self._x509, public_key._evp_pkey
        )
        assert res == 1
        return self

    def set_serial_number(self, serial_number):
        serial_number = _make_asn1_int(self._backend, serial_number)
        self._backend._lib.X509_set_serialNumber(self._x509, serial_number)
        return self

    # NOTE: this is totally incorrect!
    def set_not_valid_before(self, time):
        res = self._backend._lib.ASN1_TIME_set(
            self._backend._lib.X509_get_notBefore(self._x509),
            calendar.timegm(time.timetuple())
        )
        assert res != self._backend._ffi.NULL
        return self

    # NOTE: this is totally incorrect!
    def set_not_valid_after(self, time):
        res = self._backend._lib.ASN1_TIME_set(
            self._backend._lib.X509_get_notAfter(self._x509),
            calendar.timegm(time.timetuple())
        )
        assert res != self._backend._ffi.NULL
        return self

    def add_extension(self, extension):
        if not isinstance(extension, x509.Extension):
            raise TypeError('Expecting an x509 extension.')

        if isinstance(extension.value, x509.BasicConstraints):
            extension = _make_basic_constraints(
                self._backend,
                extension.value.ca,
                extension.value.path_length
            )
        else:
            raise ValueError('Extension not yet supported.')

        res = self._backend._lib.X509_add_ext(self._x509, extension, 0)
        assert res == 1
        return self

    def sign(self, private_key, algorithm):
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise TypeError('Algorithm must be a registered hash algorithm.')

        evp_md = self._backend._lib.EVP_get_digestbyname(
            algorithm.name.encode('ascii')
        )
        assert evp_md != self._backend._ffi.NULL

        res = self._backend._lib.X509_sign(
            self._x509, private_key._evp_pkey, evp_md
        )
        assert res > 0
        return self

    def public_bytes(self, encoding):
        if not isinstance(encoding, serialization.Encoding):
            raise TypeError("encoding must be an item from the Encoding enum")

        # TODO: make text prelude optional.
        bio = self._backend._create_mem_bio()
        res = self._backend._lib.X509_print(bio, self._x509)
        assert res == 1
        if encoding is serialization.Encoding.PEM:
            res = self._backend._lib.PEM_write_bio_X509(bio, self._x509)
        elif encoding is serialization.Encoding.DER:
            res = self._backend._lib.i2d_X509_bio(bio, self._x509)
        assert res == 1
        return self._backend._read_mem_bio(bio)


@utils.register_interface(x509.CertificateRevocationListBuilder)
class _CertificateRevocationListBuilder(object):
    def __init__(self, backend):
        self._backend = backend
        self._x509_crl = self._backend._lib.X509_CRL_new()
        assert self._x509_crl != self._backend._ffi.NULL
        self._x509_crl = self._backend._ffi.gc(
            self._x509_crl, self._backend._lib.X509_CRL_free
        )

    def set_version(self, version):
        return self

    def set_issuer_name(self, attributes):
        res = self._backend._lib.X509_CRL_set_issuer_name(
            self._x509_crl,
            _make_name(self._backend, attributes)
        )
        assert res == 1
        return self

    def set_last_update(self, time):
        res = self._backend._lib.ASN1_UTCTIME_set(
            self._x509_crl.crl.lastUpdate,
            calendar.timegm(time.timetuple())
        )
        assert res != self._backend._ffi.NULL
        return self

    def set_next_update(self, time):
        res = self._backend._lib.ASN1_UTCTIME_set(
            self._x509_crl.crl.nextUpdate,
            calendar.timegm(time.timetuple())
        )
        assert res != self._backend._ffi.NULL
        return self

    def add_extension(self, extension):
        return self

    def add_certificate(self, serial_number, revocation_date):
        # NOTE: don't GC (adding to CRL will consume reference count).
        x509_rev = self._backend._lib.X509_REVOKED_new()
        res = self._backend._lib.X509_REVOKED_set_serialNumber(
            x509_rev,
            _make_asn1_int(self._backend, serial_number)
        )
        assert res == 1
        res = self._backend._lib.ASN1_TIME_set(
            x509_rev.revocationDate,
            calendar.timegm(revocation_date.timetuple())
        )
        assert res != self._backend._ffi.NULL
        res = self._backend._lib.X509_CRL_add0_revoked(
            self._x509_crl, x509_rev
        )
        assert res == 1
        return self

    def sign(self, private_key, algorithm):
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise TypeError('Algorithm must be a registered hash algorithm.')

        evp_md = self._backend._lib.EVP_get_digestbyname(
            algorithm.name.encode('ascii')
        )
        assert evp_md != self._backend._ffi.NULL

        res = self._backend._lib.X509_CRL_sign(
            self._x509_crl, private_key._evp_pkey, evp_md
        )
        assert res > 0
        return self

    def public_bytes(self, encoding):
        if not isinstance(encoding, serialization.Encoding):
            raise TypeError("encoding must be an item from the Encoding enum")

        # TODO: make text prelude optional.
        bio = self._backend._create_mem_bio()
        res = self._backend._lib.X509_CRL_print(bio, self._x509_crl)
        assert res == 1
        if encoding is serialization.Encoding.PEM:
            res = self._backend._lib.PEM_write_bio_X509_CRL(
                bio, self._x509_crl
            )
        elif encoding is serialization.Encoding.DER:
            res = self._backend._lib.i2d_X509_CRL_bio(bio, self._x509_crl)
        assert res == 1
        return self._backend._read_mem_bio(bio)
