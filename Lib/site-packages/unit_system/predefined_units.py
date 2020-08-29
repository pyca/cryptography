"""Define commonly used units"""
from unyt import unyt_quantity, define_unit, Unit
from unit_system import Quantity

# pylint: disable=invalid-name
predefined_units = {
    "V": Quantity(1, "V"),
    "pV": Quantity(1e-12, "V"),
    "nV": Quantity(1e-9, "V"),
    "µV": Quantity(1e-6, "V"),
    "mV": Quantity(1e-3, "V"),
    "kV": Quantity(1e3, "V"),
    "A": Quantity(1, "A"),
    "pA": Quantity(1e-12, "A"),
    "nA": Quantity(1e-9, "A"),
    "µA": Quantity(1e-6, "A"),
    "mA": Quantity(1e-3, "A"),
    "kA": Quantity(1e3, "A"),
    "Ω": Quantity(1, "Ω"),
    "mΩ": Quantity(1e-3, "Ω"),
    "kΩ": Quantity(1e3, "Ω"),
    "MΩ": Quantity(1e6, "Ω"),
    "Hz": Quantity(1, "Hz"),
    "kHz": Quantity(1e3, "Hz"),
    "MHz": Quantity(1e6, "Hz"),
    "GHz": Quantity(1e9, "Hz"),
    "s": Quantity(1, "s"),
    "ps": Quantity(1e-12, "s"),
    "ns": Quantity(1e-9, "s"),
    "µs": Quantity(1e-6, "s"),
    "ms": Quantity(1e-3, "s"),
    "F": Quantity(1, "F"),
    "pF": Quantity(1e-12, "F"),
    "nF": Quantity(1e-9, "F"),
    "µF": Quantity(1e-6, "F"),
    "mF": Quantity(1e-3, "F"),
    "m": Quantity(1, "m"),
    "µm": Quantity(1e-6, "m"),
    "mm": Quantity(1e-3, "m"),
    "kg": Quantity(1, "kg"),
    "K": Quantity(1, "K"),
    "W": Quantity(1, "W"),
    "µW": Quantity(1e-6, "W"),
    "mW": Quantity(1e-3, "W"),
    "kW": Quantity(1e3, "W"),
    "J": Quantity(1, "J"),
    "µJ": Quantity(1e-6, "J"),
    "mJ": Quantity(1e-3, "J"),
    "kJ": Quantity(1e3, "J"),
    "degC": Unit("degC"),
}

define_unit("H", unyt_quantity(1, "V*s/A"), tex_repr=r"\rm{H}", prefixable=True)
predefined_units["H"] = Quantity(1, "H")
predefined_units["nH"] = Quantity(1, "nH")
predefined_units["µH"] = Quantity(1, "µH")
predefined_units["mH"] = Quantity(1, "mH")

globals().update(predefined_units)
