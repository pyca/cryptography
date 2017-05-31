# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six

from cryptography import utils


@six.add_metaclass(abc.ABCMeta)
class EllipticCurveField(object):
    """
    Field type of an EllipticCurve
    """


@utils.register_interface(EllipticCurveField)
class EllipticCurvePrimeField(object):
    def __init__(self, p):
        self._p = p

    p = utils.read_only_property("_p")

    def __eq__(self, other):
        if not isinstance(other, EllipticCurvePrimeField):
            return NotImplemented

        return self.p == other.p

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.p)

    def __repr__(self):
        return "<EllipticCurvePrimeField(p={0.p})>".format(self)


@utils.register_interface(EllipticCurveField)
class EllipticCurveBinaryField(object):
    def __init__(self, m, f):
        self._m = m
        self._f = f

    m = utils.read_only_property("_m")
    f = utils.read_only_property("_f")

    def __eq__(self, other):
        if not isinstance(other, EllipticCurveBinaryField):
            return NotImplemented

        return self.m == other.m and self.f == other.f

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.m, self.f))

    def __repr__(self):
        return "<EllipticCurveBinaryField(m={0.m}, f={0.f})>".format(self)


@six.add_metaclass(abc.ABCMeta)
class EllipticCurve(object):
    @abc.abstractproperty
    def name(self):
        """
        The name of the curve. e.g. secp256r1.
        """

    @abc.abstractproperty
    def key_size(self):
        """
        Bit size of a secret scalar for the curve.
        """

    @abc.abstractproperty
    def field(self):
        """
        The finite field associated with this curve.
        """

    @abc.abstractproperty
    def a(self):
        """
        The first constant defining the curve.
        """

    @abc.abstractproperty
    def b(self):
        """
        The second constant defining the curve.
        """

    @abc.abstractproperty
    def x(self):
        """
        The x component of the curve's base point.
        """

    @abc.abstractproperty
    def y(self):
        """
        The y component of the curve's base point.
        """

    @abc.abstractproperty
    def n(self):
        """
        The order of the curve.
        """


@six.add_metaclass(abc.ABCMeta)
class EllipticCurveSignatureAlgorithm(object):
    @abc.abstractproperty
    def algorithm(self):
        """
        The digest algorithm used with this signature.
        """


@six.add_metaclass(abc.ABCMeta)
class EllipticCurvePrivateKey(object):
    @abc.abstractmethod
    def signer(self, signature_algorithm):
        """
        Returns an AsymmetricSignatureContext used for signing data.
        """

    @abc.abstractmethod
    def exchange(self, algorithm, peer_public_key):
        """
        Performs a key exchange operation using the provided algorithm with the
        provided peer's public key.
        """

    @abc.abstractmethod
    def public_key(self):
        """
        The EllipticCurvePublicKey for this private key.
        """

    @abc.abstractproperty
    def curve(self):
        """
        The EllipticCurve that this key is on.
        """

    @abc.abstractproperty
    def key_size(self):
        """
        Bit size of a secret scalar for the curve.
        """

    @abc.abstractproperty
    def sign(self, data, signature_algorithm):
        """
        Signs the data
        """


@six.add_metaclass(abc.ABCMeta)
class EllipticCurvePrivateKeyWithSerialization(EllipticCurvePrivateKey):
    @abc.abstractmethod
    def private_numbers(self):
        """
        Returns an EllipticCurvePrivateNumbers.
        """

    @abc.abstractmethod
    def private_bytes(self, encoding, format, encryption_algorithm):
        """
        Returns the key serialized as bytes.
        """


@six.add_metaclass(abc.ABCMeta)
class EllipticCurvePublicKey(object):
    @abc.abstractmethod
    def verifier(self, signature, signature_algorithm):
        """
        Returns an AsymmetricVerificationContext used for signing data.
        """

    @abc.abstractproperty
    def curve(self):
        """
        The EllipticCurve that this key is on.
        """

    @abc.abstractproperty
    def key_size(self):
        """
        Bit size of a secret scalar for the curve.
        """

    @abc.abstractmethod
    def public_numbers(self):
        """
        Returns an EllipticCurvePublicNumbers.
        """

    @abc.abstractmethod
    def public_bytes(self, encoding, format):
        """
        Returns the key serialized as bytes.
        """

    @abc.abstractmethod
    def verify(self, signature, data, signature_algorithm):
        """
        Verifies the signature of the data.
        """


EllipticCurvePublicKeyWithSerialization = EllipticCurvePublicKey


@utils.register_interface(EllipticCurve)
class SECT571R1(object):
    name = "sect571r1"
    key_size = 571
    field = EllipticCurveBinaryField(m=571, f=(2, 5, 10))
    a = 1
    b = int("02f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1"
            "cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e29"
            "4afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a", 16)
    x = int("0303001d34b856296c16c0d40d3cd7750a93d1d2955fa80a"
            "a5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb14"
            "99ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19", 16)
    y = int("037bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca"
            "1980f8533921e8a684423e43bab08a576291af8f461bb2a8"
            "b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b", 16)
    n = int("03ffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffe661ce18ff55987308059b18"
            "6823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47", 16)


@utils.register_interface(EllipticCurve)
class SECT409R1(object):
    name = "sect409r1"
    key_size = 409
    field = EllipticCurveBinaryField(m=409, f=(87,))
    a = 1
    b = int("0021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761"
            "fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f", 16)
    x = int("015d4860d088ddb3496b0c6064756260441cde4af1771d4db01f"
            "fe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7", 16)
    y = int("0061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158"
            "aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706", 16)
    n = int("0100000000000000000000000000000000000000000000000000"
            "01e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173", 16)


@utils.register_interface(EllipticCurve)
class SECT283R1(object):
    name = "sect283r1"
    key_size = 283
    field = EllipticCurveBinaryField(m=283, f=(5, 7, 12))
    a = 1
    b = int("027b680ac8b8596da5a4af8a19a0303fca97"
            "fd7645309fa2a581485af6263e313b79a2f5", 16)
    x = int("05f939258db7dd90e1934f8c70b0dfec2eed"
            "25b8557eac9c80e2e198f8cdbecd86b12053", 16)
    y = int("03676854fe24141cb98fe6d4b20d02b4516f"
            "f702350eddb0826779c813f0df45be8112f4", 16)
    n = int("03ffffffffffffffffffffffffffffffffff"
            "ef90399660fc938a90165b042a7cefadb307", 16)


@utils.register_interface(EllipticCurve)
class SECT233R1(object):
    name = "sect233r1"
    key_size = 233
    field = EllipticCurveBinaryField(m=233, f=(74,))
    a = 1
    b = 0x0066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad
    x = 0x00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b
    y = 0x01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052
    n = 0x01000000000000000000000000000013e974e72f8a6922031d2603cfe0d7


@utils.register_interface(EllipticCurve)
class SECT163R2(object):
    name = "sect163r2"
    key_size = 163
    field = EllipticCurveBinaryField(m=163, f=(3, 6, 7))
    a = 1
    b = 0x020a601907b8c953ca1481eb10512f78744a3205fd
    x = 0x03f0eba16286a2d57ea0991168d4994637e8343e36
    y = 0x00d51fbc6c71a0094fa2cdd545b11c5c0c797324f1
    n = 0x040000000000000000000292fe77e70c12a4234c33


@utils.register_interface(EllipticCurve)
class SECT571K1(object):
    name = "sect571k1"
    key_size = 571
    field = EllipticCurveBinaryField(m=571, f=(2, 5, 10))
    a = 0
    b = 1
    x = int("026eb7a859923fbc82189631f8103fe4ac9ca2970012d5d4"
            "6024804801841ca44370958493b205e647da304db4ceb08c"
            "bbd1ba39494776fb988b47174dca88c7e2945283a01c8972", 16)
    y = int("0349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54"
            "ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedc"
            "b620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3", 16)
    n = int("020000000000000000000000000000000000000000000000"
            "000000000000000000000000131850e1f19a63e4b391a8db"
            "917f4138b630d84be5d639381e91deb45cfe778f637c1001", 16)


@utils.register_interface(EllipticCurve)
class SECT409K1(object):
    name = "sect409k1"
    key_size = 409
    field = EllipticCurveBinaryField(m=409, f=(87,))
    a = 0
    b = 1
    x = int("0060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27ac"
            "cfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746", 16)
    y = int("01e369050b7c4e42acba1dacbf04299c3460782f918ea427e632"
            "5165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b", 16)
    n = int("007fffffffffffffffffffffffffffffffffffffffffffffffff"
            "fe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf", 16)


@utils.register_interface(EllipticCurve)
class SECT283K1(object):
    name = "sect283k1"
    key_size = 283
    field = EllipticCurveBinaryField(m=283, f=(5, 7, 12))
    a = 0
    b = 1
    x = int("0503213f78ca44883f1a3b8162f188e553cd"
            "265f23c1567a16876913b0c2ac2458492836", 16)
    y = int("01ccda380f1c9e318d90f95d07e5426fe87e"
            "45c0e8184698e45962364e34116177dd2259", 16)
    n = int("01ffffffffffffffffffffffffffffffffff"
            "e9ae2ed07577265dff7f94451e061e163c61", 16)


@utils.register_interface(EllipticCurve)
class SECT233K1(object):
    name = "sect233k1"
    key_size = 233
    field = EllipticCurveBinaryField(m=233, f=(74,))
    a = 0
    b = 1
    x = 0x017232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126
    y = 0x01db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3
    n = 0x008000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf


@utils.register_interface(EllipticCurve)
class SECT163K1(object):
    name = "sect163k1"
    key_size = 163
    field = EllipticCurveBinaryField(m=163, f=(3, 6, 7))
    a = 1
    b = 1
    x = 0x02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8
    y = 0x0289070fb05d38ff58321f2e800536d538ccdaa3d9
    n = 0x04000000000000000000020108a2e0cc0d99f8a5ef


@utils.register_interface(EllipticCurve)
class SECP521R1(object):
    name = "secp521r1"
    key_size = 521
    field = EllipticCurvePrimeField(
        int("01ffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffffffffffffffff", 16)
    )
    a = int("01ffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffffffffffffffffffffffffffffffffffc", 16)
    b = int("0051953eb9618e1c9a1f929a21a0b68540eea2da725b"
            "99b315f3b8b489918ef109e156193951ec7e937b1652"
            "c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16)
    x = int("00c6858e06b70404e9cd9e3ecb662395b4429c648139"
            "053fb521f828af606b4d3dbaa14b5e77efe75928fe1d"
            "c127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16)
    y = int("011839296a789a3bc0045c8a5fb42c7d1bd998f54449"
            "579b446817afbd17273e662c97ee72995ef42640c550"
            "b9013fad0761353c7086a272c24088be94769fd16650", 16)
    n = int("01ffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffffffffffffffa51868783bf2f966b7fcc"
            "0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16)


@utils.register_interface(EllipticCurve)
class SECP384R1(object):
    name = "secp384r1"
    key_size = 384
    field = EllipticCurvePrimeField(
        int("ffffffffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffffffeffffffff0000000000000000ffffffff", 16)
    )
    a = int("ffffffffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffffffeffffffff0000000000000000fffffffc", 16)
    b = int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe814112"
            "0314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
    x = int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98"
            "59f741e082542a385502f25dbf55296c3a545e3872760ab7", 16)
    y = int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c"
            "e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)
    n = int("ffffffffffffffffffffffffffffffffffffffffffffffff"
            "c7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)


@utils.register_interface(EllipticCurve)
class SECP256R1(object):
    name = "secp256r1"
    key_size = 256
    field = EllipticCurvePrimeField(
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    )
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


@utils.register_interface(EllipticCurve)
class SECP256K1(object):
    name = "secp256k1"
    key_size = 256
    field = EllipticCurvePrimeField(
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    )
    a = 0
    b = 7
    x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


@utils.register_interface(EllipticCurve)
class SECP224R1(object):
    name = "secp224r1"
    key_size = 224
    field = EllipticCurvePrimeField(
        0xffffffffffffffffffffffffffffffff000000000000000000000001
    )
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe
    b = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4
    x = 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21
    y = 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34
    n = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d


@utils.register_interface(EllipticCurve)
class SECP192R1(object):
    name = "secp192r1"
    key_size = 192
    field = EllipticCurvePrimeField(
        0xfffffffffffffffffffffffffffffffeffffffffffffffff
    )
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    x = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
    y = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
    n = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831


_CURVE_TYPES = {
    "prime192v1": SECP192R1,
    "prime256v1": SECP256R1,

    "secp192r1": SECP192R1,
    "secp224r1": SECP224R1,
    "secp256r1": SECP256R1,
    "secp384r1": SECP384R1,
    "secp521r1": SECP521R1,
    "secp256k1": SECP256K1,

    "sect163k1": SECT163K1,
    "sect233k1": SECT233K1,
    "sect283k1": SECT283K1,
    "sect409k1": SECT409K1,
    "sect571k1": SECT571K1,

    "sect163r2": SECT163R2,
    "sect233r1": SECT233R1,
    "sect283r1": SECT283R1,
    "sect409r1": SECT409R1,
    "sect571r1": SECT571R1,
}


@utils.register_interface(EllipticCurveSignatureAlgorithm)
class ECDSA(object):
    def __init__(self, algorithm):
        self._algorithm = algorithm

    algorithm = utils.read_only_property("_algorithm")


def generate_private_key(curve, backend):
    return backend.generate_elliptic_curve_private_key(curve)


def derive_private_key(private_value, curve, backend):
    if not isinstance(private_value, six.integer_types):
        raise TypeError("private_value must be an integer type.")

    if private_value <= 0:
        raise ValueError("private_value must be a positive integer.")

    if not isinstance(curve, EllipticCurve):
        raise TypeError("curve must provide the EllipticCurve interface.")

    return backend.derive_elliptic_curve_private_key(private_value, curve)


class EllipticCurvePublicNumbers(object):
    def __init__(self, x, y, curve):
        if (
            not isinstance(x, six.integer_types) or
            not isinstance(y, six.integer_types)
        ):
            raise TypeError("x and y must be integers.")

        if not isinstance(curve, EllipticCurve):
            raise TypeError("curve must provide the EllipticCurve interface.")

        self._y = y
        self._x = x
        self._curve = curve

    def public_key(self, backend):
        return backend.load_elliptic_curve_public_numbers(self)

    def encode_point(self):
        # key_size is in bits. Convert to bytes and round up
        byte_length = (self.curve.key_size + 7) // 8
        return (
            b'\x04' + utils.int_to_bytes(self.x, byte_length) +
            utils.int_to_bytes(self.y, byte_length)
        )

    @classmethod
    def from_encoded_point(cls, curve, data):
        if not isinstance(curve, EllipticCurve):
            raise TypeError("curve must be an EllipticCurve instance")

        if data.startswith(b'\x04'):
            # key_size is in bits. Convert to bytes and round up
            byte_length = (curve.key_size + 7) // 8
            if len(data) == 2 * byte_length + 1:
                x = utils.int_from_bytes(data[1:byte_length + 1], 'big')
                y = utils.int_from_bytes(data[byte_length + 1:], 'big')
                return cls(x, y, curve)
            else:
                raise ValueError('Invalid elliptic curve point data length')
        else:
            raise ValueError('Unsupported elliptic curve point type')

    curve = utils.read_only_property("_curve")
    x = utils.read_only_property("_x")
    y = utils.read_only_property("_y")

    def __eq__(self, other):
        if not isinstance(other, EllipticCurvePublicNumbers):
            return NotImplemented

        return (
            self.x == other.x and
            self.y == other.y and
            self.curve.name == other.curve.name and
            self.curve.key_size == other.curve.key_size
        )

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.x, self.y, self.curve.name, self.curve.key_size))

    def __repr__(self):
        return (
            "<EllipticCurvePublicNumbers(curve={0.curve.name}, x={0.x}, "
            "y={0.y}>".format(self)
        )


class EllipticCurvePrivateNumbers(object):
    def __init__(self, private_value, public_numbers):
        if not isinstance(private_value, six.integer_types):
            raise TypeError("private_value must be an integer.")

        if not isinstance(public_numbers, EllipticCurvePublicNumbers):
            raise TypeError(
                "public_numbers must be an EllipticCurvePublicNumbers "
                "instance."
            )

        self._private_value = private_value
        self._public_numbers = public_numbers

    def private_key(self, backend):
        return backend.load_elliptic_curve_private_numbers(self)

    private_value = utils.read_only_property("_private_value")
    public_numbers = utils.read_only_property("_public_numbers")

    def __eq__(self, other):
        if not isinstance(other, EllipticCurvePrivateNumbers):
            return NotImplemented

        return (
            self.private_value == other.private_value and
            self.public_numbers == other.public_numbers
        )

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.private_value, self.public_numbers))


class ECDH(object):
    pass
