"""SI unit system package"""
import unyt
from unit_system.quantity import Quantity
from unit_system.predefined_units import predefined_units
from unit_system.version import __version__

unyt.matplotlib_support()
unyt.matplotlib_support.label_style = "/"
globals().update(predefined_units)
__all__ = ["Quantity"] + list(predefined_units.keys())
