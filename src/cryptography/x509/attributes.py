from cryptography import utils
from cryptography.x509.oid import ObjectIdentifier


class Attribute(object):
    def __init__(self, oid, value):
        if not isinstance(oid, ObjectIdentifier):
            raise TypeError(
                "oid argument must be an ObjectIdentifier instance."
            )

        self._oid = oid
        self._value = value

    oid = utils.read_only_property("_oid")
    value = utils.read_only_property("_value")

    def __repr__(self):
        return ("<Attribute(oid={0.oid}, value={0.value})>").format(self)

    def __eq__(self, other):
        if not isinstance(other, Attribute):
            return NotImplemented

        return (
            self.oid == other.oid and
            self.value == other.value
        )

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.oid, self.value))
