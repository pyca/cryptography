# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


<<<<<<< HEAD
import binascii
import collections
import json
import os
import re
import typing
from contextlib import contextmanager
=======
import abc
import inspect
import sys
import typing
import warnings
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0


# We use a UserWarning subclass, instead of DeprecationWarning, because CPython
# decided deprecation warnings should be invisble by default.
class CryptographyDeprecationWarning(UserWarning):
    pass


# Several APIs were deprecated with no specific end-of-life date because of the
# ubiquity of their use. They should not be removed until we agree on when that
# cycle ends.
PersistentlyDeprecated2017 = CryptographyDeprecationWarning
PersistentlyDeprecated2019 = CryptographyDeprecationWarning
DeprecatedIn34 = CryptographyDeprecationWarning


def _check_bytes(name: str, value: bytes):
    if not isinstance(value, bytes):
        raise TypeError("{} must be bytes".format(name))


def _check_byteslike(name: str, value: bytes):
    try:
        memoryview(value)
    except TypeError:
        raise TypeError("{} must be bytes-like".format(name))


def read_only_property(name: str):
    return property(lambda self: getattr(self, name))


<<<<<<< HEAD
def load_nist_vectors(vector_data):
    test_data = {}
    data = []
=======
def register_interface(iface):
    def register_decorator(klass, *, check_annotations=False):
        verify_interface(iface, klass, check_annotations=check_annotations)
        iface.register(klass)
        return klass
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0

    return register_decorator


def register_interface_if(predicate, iface):
    def register_decorator(klass, *, check_annotations=False):
        if predicate:
            verify_interface(iface, klass, check_annotations=check_annotations)
            iface.register(klass)
        return klass

    return register_decorator


def int_to_bytes(integer: int, length: typing.Optional[int] = None) -> bytes:
    return integer.to_bytes(
        length or (integer.bit_length() + 7) // 8 or 1, "big"
    )


class InterfaceNotImplemented(Exception):
    pass


def strip_annotation(signature):
    return inspect.Signature(
        [
            param.replace(annotation=inspect.Parameter.empty)
            for param in signature.parameters.values()
        ]
    )


def verify_interface(iface, klass, *, check_annotations=False):
    for method in iface.__abstractmethods__:
        if not hasattr(klass, method):
            raise InterfaceNotImplemented(
                "{} is missing a {!r} method".format(klass, method)
            )
<<<<<<< HEAD
        else:
            raise ValueError("Invalid line in file '{}'".format(line))
    return cryptrec_list


def load_hash_vectors(vector_data):
    vectors: typing.List[typing.Union[KeyedHashVector, HashVector]] = []
    key = None
    msg = None
    md = None

    for line in vector_data:
        line = line.strip()

        if not line or line.startswith("#") or line.startswith("["):
            continue

        if line.startswith("Len"):
            length = int(line.split(" = ")[1])
        elif line.startswith("Key"):
            # HMAC vectors contain a key attribute. Hash vectors do not.
            key = line.split(" = ")[1].encode("ascii")
        elif line.startswith("Msg"):
            # In the NIST vectors they have chosen to represent an empty
            # string as hex 00, which is of course not actually an empty
            # string. So we parse the provided length and catch this edge case.
            msg = line.split(" = ")[1].encode("ascii") if length > 0 else b""
        elif line.startswith("MD") or line.startswith("Output"):
            md = line.split(" = ")[1]
            # after MD is found the Msg+MD (+ potential key) tuple is complete
            if key is not None:
                vectors.append(KeyedHashVector(msg, md, key))
                key = None
                msg = None
                md = None
            else:
                vectors.append(HashVector(msg, md))
                msg = None
                md = None
        else:
            raise ValueError("Unknown line in hash vector")
    return vectors


def load_pkcs1_vectors(vector_data):
    """
    Loads data out of RSA PKCS #1 vector files.
    """
    private_key_vector: typing.Optional[typing.Dict[str, typing.Any]] = None
    public_key_vector: typing.Optional[typing.Dict[str, typing.Any]] = None
    attr = None
    key: typing.Any = None
    example_vector: typing.Optional[typing.Dict[str, typing.Any]] = None
    examples = []
    vectors = []
    for line in vector_data:
        if (
            line.startswith("# PSS Example")
            or line.startswith("# OAEP Example")
            or line.startswith("# PKCS#1 v1.5")
        ):
            if example_vector:
                for key, value in example_vector.items():
                    hex_bytes = "".join(value).replace(" ", "").encode("ascii")
                    example_vector[key] = hex_bytes
                examples.append(example_vector)

            attr = None
            example_vector = collections.defaultdict(list)

        if line.startswith("# Message"):
            attr = "message"
            continue
        elif line.startswith("# Salt"):
            attr = "salt"
            continue
        elif line.startswith("# Seed"):
            attr = "seed"
            continue
        elif line.startswith("# Signature"):
            attr = "signature"
            continue
        elif line.startswith("# Encryption"):
            attr = "encryption"
            continue
        elif example_vector and line.startswith(
            "# ============================================="
        ):
            for key, value in example_vector.items():
                hex_bytes = "".join(value).replace(" ", "").encode("ascii")
                example_vector[key] = hex_bytes
            examples.append(example_vector)
            example_vector = None
            attr = None
        elif example_vector and line.startswith("#"):
            continue
        else:
            if attr is not None and example_vector is not None:
                example_vector[attr].append(line.strip())
                continue

        if line.startswith("# Example") or line.startswith(
            "# ============================================="
        ):
            if key:
                assert private_key_vector
                assert public_key_vector

                for key, value in public_key_vector.items():
                    hex_str = "".join(value).replace(" ", "")
                    public_key_vector[key] = int(hex_str, 16)

                for key, value in private_key_vector.items():
                    hex_str = "".join(value).replace(" ", "")
                    private_key_vector[key] = int(hex_str, 16)

                private_key_vector["examples"] = examples
                examples = []

                assert (
                    private_key_vector["public_exponent"]
                    == public_key_vector["public_exponent"]
                )

                assert (
                    private_key_vector["modulus"]
                    == public_key_vector["modulus"]
                )

                vectors.append((private_key_vector, public_key_vector))

            public_key_vector = collections.defaultdict(list)
            private_key_vector = collections.defaultdict(list)
            key = None
            attr = None

        if private_key_vector is None or public_key_vector is None:
            # Random garbage to defeat CPython's peephole optimizer so that
            # coverage records correctly: https://bugs.python.org/issue2506
            1 + 1
            continue

        if line.startswith("# Private key"):
            key = private_key_vector
        elif line.startswith("# Public key"):
            key = public_key_vector
        elif line.startswith("# Modulus:"):
            attr = "modulus"
        elif line.startswith("# Public exponent:"):
            attr = "public_exponent"
        elif line.startswith("# Exponent:"):
            if key is public_key_vector:
                attr = "public_exponent"
            else:
                assert key is private_key_vector
                attr = "private_exponent"
        elif line.startswith("# Prime 1:"):
            attr = "p"
        elif line.startswith("# Prime 2:"):
            attr = "q"
        elif line.startswith("# Prime exponent 1:"):
            attr = "dmp1"
        elif line.startswith("# Prime exponent 2:"):
            attr = "dmq1"
        elif line.startswith("# Coefficient:"):
            attr = "iqmp"
        elif line.startswith("#"):
            attr = None
        else:
            if key is not None and attr is not None:
                key[attr].append(line.strip())
    return vectors


def load_rsa_nist_vectors(vector_data):
    test_data: typing.Dict[str, typing.Any] = {}
    p = None
    salt_length = None
    data = []

    for line in vector_data:
        line = line.strip()

        # Blank lines and section headers are ignored
        if not line or line.startswith("["):
            continue

        if line.startswith("# Salt len:"):
            salt_length = int(line.split(":")[1].strip())
            continue
        elif line.startswith("#"):
=======
        if isinstance(getattr(iface, method), abc.abstractproperty):
            # Can't properly verify these yet.
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0
            continue
        sig = inspect.signature(getattr(iface, method))
        actual = inspect.signature(getattr(klass, method))
        if check_annotations:
            ok = sig == actual
        else:
            ok = strip_annotation(sig) == strip_annotation(actual)
        if not ok:
            raise InterfaceNotImplemented(
                "{}.{}'s signature differs from the expected. Expected: "
                "{!r}. Received: {!r}".format(klass, method, sig, actual)
            )


class _DeprecatedValue(object):
    def __init__(self, value, message, warning_class):
        self.value = value
        self.message = message
        self.warning_class = warning_class


class _ModuleWithDeprecations(object):
    def __init__(self, module):
        self.__dict__["_module"] = module

    def __getattr__(self, attr):
        obj = getattr(self._module, attr)
        if isinstance(obj, _DeprecatedValue):
            warnings.warn(obj.message, obj.warning_class, stacklevel=2)
            obj = obj.value
        return obj

<<<<<<< HEAD
    vectors = []
    data: typing.Dict[str, typing.Any] = {"fail_z": False, "fail_agree": False}
=======
    def __setattr__(self, attr, value):
        setattr(self._module, attr, value)
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0

    def __delattr__(self, attr):
        obj = getattr(self._module, attr)
        if isinstance(obj, _DeprecatedValue):
            warnings.warn(obj.message, obj.warning_class, stacklevel=2)

<<<<<<< HEAD
        if not line or line.startswith("#"):
            continue

        if line.startswith("P = "):
            data["p"] = int(line.split("=")[1], 16)
        elif line.startswith("Q = "):
            data["q"] = int(line.split("=")[1], 16)
        elif line.startswith("G = "):
            data["g"] = int(line.split("=")[1], 16)
        elif line.startswith("Z = "):
            z_hex = line.split("=")[1].strip().encode("ascii")
            data["z"] = binascii.unhexlify(z_hex)
        elif line.startswith("XstatCAVS = "):
            data["x1"] = int(line.split("=")[1], 16)
        elif line.startswith("YstatCAVS = "):
            data["y1"] = int(line.split("=")[1], 16)
        elif line.startswith("XstatIUT = "):
            data["x2"] = int(line.split("=")[1], 16)
        elif line.startswith("YstatIUT = "):
            data["y2"] = int(line.split("=")[1], 16)
        elif line.startswith("Result = "):
            result_str = line.split("=")[1].strip()
            match = result_rx.match(result_str)
            assert match is not None

            if match.group(1) == "F":
                if int(match.group(2)) in (5, 10):
                    data["fail_z"] = True
                else:
                    data["fail_agree"] = True

            vectors.append(data)

            data = {
                "p": data["p"],
                "q": data["q"],
                "g": data["g"],
                "fail_z": False,
                "fail_agree": False,
            }

    return vectors


def load_kasvs_ecdh_vectors(vector_data):
    """
    Loads data out of the KASVS key exchange vector data
    """

    curve_name_map = {
        "P-192": "secp192r1",
        "P-224": "secp224r1",
        "P-256": "secp256r1",
        "P-384": "secp384r1",
        "P-521": "secp521r1",
    }

    result_rx = re.compile(r"([FP]) \(([0-9]+) -")

    tags = []
    sets = {}
    vectors = []

    # find info in header
    for line in vector_data:
        line = line.strip()

        if line.startswith("#"):
            parm = line.split("Parameter set(s) supported:")
            if len(parm) == 2:
                names = parm[1].strip().split()
                for n in names:
                    tags.append("[%s]" % n)
                break

    # Sets Metadata
    tag = None
    curve = None
    for line in vector_data:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line in tags:
            tag = line
            curve = None
        elif line.startswith("[Curve selected:"):
            curve = curve_name_map[line.split(":")[1].strip()[:-1]]

        if tag is not None and curve is not None:
            sets[tag.strip("[]")] = curve
            tag = None
        if len(tags) == len(sets):
            break

    # Data
    data: typing.Dict[str, typing.Any] = {
        "CAVS": {},
        "IUT": {},
    }
    tag = None
    for line in vector_data:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("["):
            tag = line.split()[0][1:]
        elif line.startswith("COUNT = "):
            data["COUNT"] = int(line.split("=")[1])
        elif line.startswith("dsCAVS = "):
            data["CAVS"]["d"] = int(line.split("=")[1], 16)
        elif line.startswith("QsCAVSx = "):
            data["CAVS"]["x"] = int(line.split("=")[1], 16)
        elif line.startswith("QsCAVSy = "):
            data["CAVS"]["y"] = int(line.split("=")[1], 16)
        elif line.startswith("dsIUT = "):
            data["IUT"]["d"] = int(line.split("=")[1], 16)
        elif line.startswith("QsIUTx = "):
            data["IUT"]["x"] = int(line.split("=")[1], 16)
        elif line.startswith("QsIUTy = "):
            data["IUT"]["y"] = int(line.split("=")[1], 16)
        elif line.startswith("OI = "):
            data["OI"] = int(line.split("=")[1], 16)
        elif line.startswith("Z = "):
            data["Z"] = int(line.split("=")[1], 16)
        elif line.startswith("DKM = "):
            data["DKM"] = int(line.split("=")[1], 16)
        elif line.startswith("Result = "):
            result_str = line.split("=")[1].strip()
            match = result_rx.match(result_str)
            assert match is not None

            if match.group(1) == "F":
                data["fail"] = True
            else:
                data["fail"] = False
            data["errno"] = int(match.group(2))

            data["curve"] = sets[tag]

            vectors.append(data)

            data = {
                "CAVS": {},
                "IUT": {},
            }

    return vectors


def load_x963_vectors(vector_data):
    """
    Loads data out of the X9.63 vector data
    """

    vectors = []

    # Sets Metadata
    hashname = None
    vector = {}
    for line in vector_data:
        line = line.strip()

        if line.startswith("[SHA"):
            hashname = line[1:-1]
            shared_secret_len = 0
            shared_info_len = 0
            key_data_len = 0
        elif line.startswith("[shared secret length"):
            shared_secret_len = int(line[1:-1].split("=")[1].strip())
        elif line.startswith("[SharedInfo length"):
            shared_info_len = int(line[1:-1].split("=")[1].strip())
        elif line.startswith("[key data length"):
            key_data_len = int(line[1:-1].split("=")[1].strip())
        elif line.startswith("COUNT"):
            count = int(line.split("=")[1].strip())
            vector["hash"] = hashname
            vector["count"] = count
            vector["shared_secret_length"] = shared_secret_len
            vector["sharedinfo_length"] = shared_info_len
            vector["key_data_length"] = key_data_len
        elif line.startswith("Z"):
            vector["Z"] = line.split("=")[1].strip()
            assert vector["Z"] is not None
            assert ((shared_secret_len + 7) // 8) * 2 == len(vector["Z"])
        elif line.startswith("SharedInfo"):
            if shared_info_len != 0:
                vector["sharedinfo"] = line.split("=")[1].strip()
                assert vector["sharedinfo"] is not None
                silen = len(vector["sharedinfo"])
                assert ((shared_info_len + 7) // 8) * 2 == silen
        elif line.startswith("key_data"):
            vector["key_data"] = line.split("=")[1].strip()
            assert vector["key_data"] is not None
            assert ((key_data_len + 7) // 8) * 2 == len(vector["key_data"])
            vectors.append(vector)
            vector = {}

    return vectors


def load_nist_kbkdf_vectors(vector_data):
    """
    Load NIST SP 800-108 KDF Vectors
    """
    vectors = []
    test_data = None
    tag = {}

    for line in vector_data:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("[") and line.endswith("]"):
            tag_data = line[1:-1]
            name, value = [c.strip() for c in tag_data.split("=")]
            if value.endswith("_BITS"):
                value = int(value.split("_")[0])
                tag.update({name.lower(): value})
                continue

            tag.update({name.lower(): value.lower()})
        elif line.startswith("COUNT="):
            test_data = {}
            test_data.update(tag)
            vectors.append(test_data)
        elif line.startswith("L"):
            name, value = [c.strip() for c in line.split("=")]
            test_data[name.lower()] = int(value)
        else:
            name, value = [c.strip() for c in line.split("=")]
            test_data[name.lower()] = value.encode("ascii")

    return vectors


def load_ed25519_vectors(vector_data):
    data = []
    for line in vector_data:
        secret_key, public_key, message, signature, _ = line.split(":")
        # In the vectors the first element is secret key + public key
        secret_key = secret_key[0:64]
        # In the vectors the signature section is signature + message
        signature = signature[0:128]
        data.append(
            {
                "secret_key": secret_key,
                "public_key": public_key,
                "message": message,
                "signature": signature,
            }
        )
    return data


def load_nist_ccm_vectors(vector_data):
    test_data = {}
    section_data = None
    global_data = {}
    new_section = False
    data = []

    for line in vector_data:
        line = line.strip()

        # Blank lines and comments should be ignored
        if not line or line.startswith("#"):
            continue

        # Some of the CCM vectors have global values for this. They are always
        # at the top before the first section header (see: VADT, VNT, VPT)
        if line.startswith(("Alen", "Plen", "Nlen", "Tlen")):
            name, value = [c.strip() for c in line.split("=")]
            global_data[name.lower()] = int(value)
            continue
=======
        delattr(self._module, attr)
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0

    def __dir__(self):
        return ["_module"] + dir(self._module)


def deprecated(value, module_name, message, warning_class):
    module = sys.modules[module_name]
    if not isinstance(module, _ModuleWithDeprecations):
        sys.modules[module_name] = _ModuleWithDeprecations(
            module
        )  # type: ignore[assignment]
    return _DeprecatedValue(value, message, warning_class)


def cached_property(func):
    cached_name = "_cached_{}".format(func)
    sentinel = object()

    def inner(instance):
        cache = getattr(instance, cached_name, sentinel)
        if cache is not sentinel:
            return cache
        result = func(instance)
        setattr(instance, cached_name, result)
        return result

    return property(inner)


int_from_bytes = deprecated(
    int.from_bytes,
    __name__,
    "int_from_bytes is deprecated, use int.from_bytes instead",
    DeprecatedIn34,
)
