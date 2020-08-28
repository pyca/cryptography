"""
Predefined useful physical constants

Note that all of these names can be imported from the top-level unyt namespace.
For example::

    >>> from unyt.physical_constants import gravitational_constant, solar_mass
    >>> from unyt import AU
    >>> from math import pi
    >>>
    >>> period = 2 * pi * ((1 * AU)**3 / (gravitational_constant * solar_mass))**0.5
    >>> period.in_units('day')
    unyt_quantity(365.26236846, 'day')

.. show_all_constants::

"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------

from unyt.unit_registry import default_unit_registry as _default_unit_registry
from unyt.unit_systems import add_constants as _add_constants

_add_constants(globals(), registry=_default_unit_registry)
