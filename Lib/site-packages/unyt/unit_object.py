"""
A class that represents a unit symbol.


"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------


import copy
import itertools
import math
import numpy as np
from functools import lru_cache
from numbers import Number as numeric_type

from sympy import (
    Expr,
    Mul,
    Add,
    Number,
    Pow,
    Symbol,
    Float,
    Basic,
    Rational,
    Mod,
    floor,
)
from sympy.core.numbers import One
from sympy import sympify, latex

from unyt.dimensions import (
    angle,
    base_dimensions,
    dimensionless,
    temperature,
    current_mks,
    logarithmic,
)
import unyt.dimensions as dims
from unyt.equivalencies import equivalence_registry
from unyt.exceptions import (
    InvalidUnitOperation,
    MissingMKSCurrent,
    MKSCGSConversionError,
    UnitConversionError,
    UnitsNotReducible,
    UnitParseError,
)
from unyt._parsing import parse_unyt_expr
from unyt._physical_ratios import speed_of_light_cm_per_s
from unyt.unit_registry import default_unit_registry, _lookup_unit_symbol, UnitRegistry
from unyt.unit_systems import _split_prefix

sympy_one = sympify(1)


def _get_latex_representation(expr, registry):
    symbol_table = {}
    for ex in expr.free_symbols:
        try:
            symbol_table[ex] = registry.lut[str(ex)][3]
        except KeyError:
            symbol_table[ex] = r"\rm{" + str(ex).replace("_", r"\ ") + "}"

    # invert the symbol table dict to look for keys with identical values
    invert_symbols = {}
    for key, value in symbol_table.items():
        if value not in invert_symbols:
            invert_symbols[value] = [key]
        else:
            invert_symbols[value].append(key)

    # if there are any units with identical latex representations, substitute
    # units to avoid  uncanceled terms in the final latex expression.
    for val in invert_symbols:
        symbols = invert_symbols[val]
        for i in range(1, len(symbols)):
            expr = expr.subs(symbols[i], symbols[0])
    prefix = None
    l_expr = expr
    if isinstance(expr, Mul):
        coeffs = expr.as_coeff_Mul()
        if coeffs[0] == 1 or not isinstance(coeffs[0], Number):
            l_expr = coeffs[1]
        else:
            l_expr = coeffs[1]
            prefix = Float(coeffs[0], 2)
    latex_repr = latex(
        l_expr,
        symbol_names=symbol_table,
        mul_symbol="dot",
        fold_frac_powers=True,
        fold_short_frac=True,
    )

    if prefix is not None:
        latex_repr = latex(prefix, mul_symbol="times") + "\\ " + latex_repr

    if latex_repr == "1":
        return ""
    else:
        return latex_repr


class _ImportCache(object):

    __slots__ = ["_ua", "_uq"]

    def __init__(self):
        self._ua = None
        self._uq = None

    @property
    def ua(self):
        if self._ua is None:
            from unyt.array import unyt_array

            self._ua = unyt_array
        return self._ua

    @property
    def uq(self):
        if self._uq is None:
            from unyt.array import unyt_quantity

            self._uq = unyt_quantity
        return self._uq


_import_cache_singleton = _ImportCache()


class Unit(object):
    """
    A symbolic unit, using sympy functionality. We only add "dimensions" so
    that sympy understands relations between different units.

    """

    __slots__ = [
        "expr",
        "is_atomic",
        "base_value",
        "base_offset",
        "dimensions",
        "_latex_repr",
        "registry",
        "is_Unit",
    ]

    # Set some assumptions for sympy.
    is_positive = True  # make sqrt(m**2) --> m
    is_commutative = True
    is_number = False

    __array_priority__ = 3.0

    def __new__(
        cls,
        unit_expr=sympy_one,
        base_value=None,
        base_offset=0.0,
        dimensions=None,
        registry=None,
        latex_repr=None,
    ):
        """
        Create a new unit. May be an atomic unit (like a gram) or combinations
        of atomic units (like g / cm**3).

        Parameters
        ----------
        unit_expr : Unit object, sympy.core.expr.Expr object, or str
            The symbolic unit expression.
        base_value : float
            The unit's value in yt's base units.
        base_offset : float
            The offset necessary to normalize temperature units to a common
            zero point.
        dimensions : sympy.core.expr.Expr
            A sympy expression representing the dimensionality of this unit.
            It must contain only mass, length, time, temperature and angle
            symbols.
        registry : UnitRegistry object
            The unit registry we use to interpret unit symbols.
        latex_repr : string
            A string to render the unit as LaTeX

        """
        unit_cache_key = None
        # Simplest case. If user passes a Unit object, just use the expr.
        if hasattr(unit_expr, "is_Unit"):
            # grab the unit object's sympy expression.
            unit_expr = unit_expr.expr
        elif hasattr(unit_expr, "units") and hasattr(unit_expr, "value"):
            # something that looks like a unyt_array, grab the unit and value
            if unit_expr.shape != ():
                raise UnitParseError(
                    "Cannot create a unit from a non-scalar unyt_array, "
                    "received: %s" % (unit_expr,)
                )
            value = unit_expr.value
            if value == 1:
                unit_expr = unit_expr.units.expr
            else:
                unit_expr = unit_expr.value * unit_expr.units.expr
        # Parse a text unit representation using sympy's parser
        elif isinstance(unit_expr, (str, bytes)):
            if isinstance(unit_expr, bytes):
                unit_expr = unit_expr.decode("utf-8")

            # this cache substantially speeds up unit conversions
            if registry and unit_expr in registry._unit_object_cache:
                return registry._unit_object_cache[unit_expr]
            unit_cache_key = unit_expr
            unit_expr = parse_unyt_expr(unit_expr)
        # Make sure we have an Expr at this point.
        if not isinstance(unit_expr, Expr):
            raise UnitParseError(
                "Unit representation must be a string or "
                "sympy Expr. '%s' has type '%s'." % (unit_expr, type(unit_expr))
            )

        if dimensions is None and unit_expr is sympy_one:
            dimensions = dimensionless

        if registry is None:
            # Caller did not set the registry, so use the default.
            registry = default_unit_registry

        # done with argument checking...

        # see if the unit is atomic.
        is_atomic = False
        if isinstance(unit_expr, Symbol):
            is_atomic = True

        #
        # check base_value and dimensions
        #

        if base_value is not None:
            # check that base_value is a float or can be converted to one
            try:
                base_value = float(base_value)
            except ValueError:
                raise UnitParseError(
                    "Could not use base_value as a float. "
                    "base_value is '%s' (type '%s')." % (base_value, type(base_value))
                )

            # check that dimensions is valid
            if dimensions is not None:
                _validate_dimensions(dimensions)
        else:
            # lookup the unit symbols
            unit_data = _get_unit_data_from_expr(unit_expr, registry.lut)
            base_value = unit_data[0]
            dimensions = unit_data[1]
            if len(unit_data) > 2:
                base_offset = unit_data[2]
                latex_repr = unit_data[3]
            else:
                base_offset = 0.0

        # Create obj with superclass construct.
        obj = super(Unit, cls).__new__(cls)

        # Attach attributes to obj.
        obj.expr = unit_expr
        obj.is_atomic = is_atomic
        obj.base_value = base_value
        obj.base_offset = base_offset
        obj.dimensions = dimensions
        obj._latex_repr = latex_repr
        obj.registry = registry
        # lets us avoid isinstance calls
        obj.is_Unit = True

        # if we parsed a string unit expression, cache the result
        # for faster lookup later
        if unit_cache_key is not None:
            registry._unit_object_cache[unit_cache_key] = obj

        # Return `obj` so __init__ can handle it.

        return obj

    @property
    def latex_repr(self):
        """A LaTeX representation for the unit

        Examples
        --------
        >>> from unyt import g, cm
        >>> (g/cm**3).units.latex_repr
        '\\\\frac{\\\\rm{g}}{\\\\rm{cm}^{3}}'
        """
        if self._latex_repr is not None:
            return self._latex_repr
        if self.expr.is_Atom:
            expr = self.expr
        else:
            expr = self.expr.copy()
        self._latex_repr = _get_latex_representation(expr, self.registry)
        return self._latex_repr

    @property
    def units(self):
        return self

    def __hash__(self):
        return int(self.registry.unit_system_id, 16) ^ hash(self.expr)

    # end sympy conventions

    def __repr__(self):
        if self.expr == sympy_one:
            return "(dimensionless)"
        # @todo: don't use dunder method?
        return self.expr.__repr__()

    def __str__(self):
        if self.expr == sympy_one:
            return "dimensionless"
        unit_str = self.expr.__str__()
        if unit_str == "degC":
            return "°C"
        if unit_str == "degF":
            return "°F"
        # @todo: don't use dunder method?
        return unit_str

    #
    # Start unit operations
    #

    def __add__(self, u):
        raise InvalidUnitOperation("addition with unit objects is not allowed")

    def __radd__(self, u):
        raise InvalidUnitOperation("addition with unit objects is not allowed")

    def __sub__(self, u):
        raise InvalidUnitOperation("subtraction with unit objects is not allowed")

    def __rsub__(self, u):
        raise InvalidUnitOperation("subtraction with unit objects is not allowed")

    def __iadd__(self, u):
        raise InvalidUnitOperation(
            "in-place operations with unit objects are not allowed"
        )

    def __isub__(self, u):
        raise InvalidUnitOperation(
            "in-place operations with unit objects are not allowed"
        )

    def __imul__(self, u):
        raise InvalidUnitOperation(
            "in-place operations with unit objects are not allowed"
        )

    def __itruediv__(self, u):
        raise InvalidUnitOperation(
            "in-place operations with unit objects are not allowed"
        )

    def __rmul__(self, u):
        return self.__mul__(u)

    def __mul__(self, u):
        """ Multiply Unit with u (Unit object). """
        if not getattr(u, "is_Unit", False):
            data = np.array(u, subok=True)
            unit = getattr(u, "units", None)
            if unit is not None:
                if self.dimensions is logarithmic:
                    raise InvalidUnitOperation(
                        "Tried to multiply '%s' and '%s'." % (self, unit)
                    )
                units = unit * self
            else:
                units = self
            if data.dtype.kind not in ("f", "u", "i", "c"):
                raise InvalidUnitOperation(
                    "Tried to multiply a Unit object with '%s' (type %s). "
                    "This behavior is undefined." % (u, type(u))
                )
            if data.shape == ():
                return _import_cache_singleton.uq(data, units, bypass_validation=True)
            return _import_cache_singleton.ua(data, units, bypass_validation=True)
        elif self.dimensions is logarithmic and not u.is_dimensionless:
            raise InvalidUnitOperation("Tried to multiply '%s' and '%s'." % (self, u))
        elif u.dimensions is logarithmic and not self.is_dimensionless:
            raise InvalidUnitOperation("Tried to multiply '%s' and '%s'." % (self, u))

        base_offset = 0.0
        if self.base_offset or u.base_offset:
            if u.dimensions in (temperature, angle) and self.is_dimensionless:
                base_offset = u.base_offset
            elif self.dimensions in (temperature, angle) and u.is_dimensionless:
                base_offset = self.base_offset
            else:
                raise InvalidUnitOperation(
                    "Quantities with dimensions of angle or units of "
                    "Fahrenheit or Celsius cannot be multiplied."
                )

        return Unit(
            self.expr * u.expr,
            base_value=(self.base_value * u.base_value),
            base_offset=base_offset,
            dimensions=(self.dimensions * u.dimensions),
            registry=self.registry,
        )

    def __truediv__(self, u):
        """ Divide Unit by u (Unit object). """
        if not isinstance(u, Unit):
            if isinstance(u, (numeric_type, list, tuple, np.ndarray)):
                from unyt.array import unyt_quantity

                return unyt_quantity(1.0, self) / u
            else:
                raise InvalidUnitOperation(
                    "Tried to divide a Unit object by '%s' (type %s). This "
                    "behavior is undefined." % (u, type(u))
                )
        elif self.dimensions is logarithmic and not u.is_dimensionless:
            raise InvalidUnitOperation("Tried to divide '%s' and '%s'." % (self, u))
        elif u.dimensions is logarithmic and not self.is_dimensionless:
            raise InvalidUnitOperation("Tried to divide '%s' and '%s'." % (self, u))

        base_offset = 0.0
        if self.base_offset or u.base_offset:
            if self.dimensions in (temperature, angle) and u.is_dimensionless:
                base_offset = self.base_offset
            else:
                raise InvalidUnitOperation(
                    "Quantities with units of Farhenheit "
                    "and Celsius cannot be divided."
                )

        return Unit(
            self.expr / u.expr,
            base_value=(self.base_value / u.base_value),
            base_offset=base_offset,
            dimensions=(self.dimensions / u.dimensions),
            registry=self.registry,
        )

    def __rtruediv__(self, u):
        return u * self ** -1

    def __pow__(self, p):
        """ Take Unit to power p (float). """
        try:
            p = Rational(str(p)).limit_denominator()
        except (ValueError, TypeError):
            raise InvalidUnitOperation(
                "Tried to take a Unit object to the "
                "power '%s' (type %s). Failed to cast "
                "it to a float." % (p, type(p))
            )

        if self.dimensions is logarithmic and p != 1.0:
            raise InvalidUnitOperation("Tried to raise '%s' to power '%s'" % (self, p))

        return Unit(
            self.expr ** p,
            base_value=(self.base_value ** p),
            dimensions=(self.dimensions ** p),
            registry=self.registry,
        )

    def __eq__(self, u):
        """ Test unit equality. """
        if not isinstance(u, Unit):
            return False
        return (
            math.isclose(self.base_value, u.base_value)
            and self.dimensions == u.dimensions
        )

    def __ne__(self, u):
        """ Test unit inequality. """
        if not isinstance(u, Unit):
            return True
        if not math.isclose(self.base_value, u.base_value):
            return True
        # use 'is' comparison dimensions to avoid expensive sympy operation
        if self.dimensions is u.dimensions:
            return False
        # fall back to expensive sympy comparison
        return self.dimensions != u.dimensions

    def copy(self):
        return copy.deepcopy(self)

    def __deepcopy__(self, memodict=None):
        expr = str(self.expr)
        base_value = copy.deepcopy(self.base_value)
        base_offset = copy.deepcopy(self.base_offset)
        dimensions = copy.deepcopy(self.dimensions)
        lut = copy.deepcopy(self.registry.lut)
        registry = UnitRegistry(lut=lut)
        return Unit(expr, base_value, base_offset, dimensions, registry)

    #
    # End unit operations
    #

    def same_dimensions_as(self, other_unit):
        """Test if the dimensions of *other_unit* are the same as this unit

        Examples
        --------
        >>> from unyt import Msun, kg, mile
        >>> Msun.units.same_dimensions_as(kg.units)
        True
        >>> Msun.units.same_dimensions_as(mile.units)
        False
        """
        # test first for 'is' equality to avoid expensive sympy operation
        if self.dimensions is other_unit.dimensions:
            return True
        return (self.dimensions / other_unit.dimensions) == sympy_one

    @property
    def is_dimensionless(self):
        """Is this a dimensionless unit?

        Returns
        -------
        True for a dimensionless unit, False otherwise

        Examples
        --------
        >>> from unyt import count, kg
        >>> count.units.is_dimensionless
        True
        >>> kg.units.is_dimensionless
        False
        """
        return self.dimensions is sympy_one

    @property
    def is_code_unit(self):
        """Is this a "code" unit?

        Returns
        -------
        True if the unit consists of atom units that being with "code".
        False otherwise

        """
        for atom in self.expr.atoms():
            if not (str(atom).startswith("code") or atom.is_Number):
                return False
        return True

    def list_equivalencies(self):
        """Lists the possible equivalencies associated with this unit object

        Examples
        --------
        >>> from unyt import km
        >>> km.units.list_equivalencies()
        spectral: length <-> spatial_frequency <-> frequency <-> energy
        schwarzschild: mass <-> length
        compton: mass <-> length
        """
        from unyt.equivalencies import equivalence_registry

        for k, v in equivalence_registry.items():
            if self.has_equivalent(k):
                print(v())

    def has_equivalent(self, equiv):
        """
        Check to see if this unit object as an equivalent unit in *equiv*.

        Example
        -------
        >>> from unyt import km
        >>> km.has_equivalent('spectral')
        True
        >>> km.has_equivalent('mass_energy')
        False
        """
        try:
            this_equiv = equivalence_registry[equiv]()
        except KeyError:
            raise KeyError('No such equivalence "%s".' % equiv)
        old_dims = self.dimensions
        return old_dims in this_equiv._dims

    def get_base_equivalent(self, unit_system=None):
        """Create and return dimensionally-equivalent units in a specified base.

        >>> from unyt import g, cm
        >>> (g/cm**3).get_base_equivalent('mks')
        kg/m**3
        >>> (g/cm**3).get_base_equivalent('solar')
        Mearth/AU**3
        """
        from unyt.unit_registry import _sanitize_unit_system

        unit_system = _sanitize_unit_system(unit_system, self)
        try:
            conv_data = _check_em_conversion(
                self.units, registry=self.registry, unit_system=unit_system
            )
            um = unit_system.units_map
            if self.dimensions in um and self.expr == um[self.dimensions]:
                return self.copy()
        except MKSCGSConversionError:
            raise UnitsNotReducible(self.units, unit_system)
        if any(conv_data):
            new_units, _ = _em_conversion(self, conv_data, unit_system=unit_system)
        else:
            try:
                new_units = unit_system[self.dimensions]
            except MissingMKSCurrent:
                raise UnitsNotReducible(self.units, unit_system)
        return Unit(new_units, registry=self.registry)

    def get_cgs_equivalent(self):
        """Create and return dimensionally-equivalent cgs units.

        Example
        -------
        >>> from unyt import kg, m
        >>> (kg/m**3).get_cgs_equivalent()
        g/cm**3
        """
        return self.get_base_equivalent(unit_system="cgs")

    def get_mks_equivalent(self):
        """Create and return dimensionally-equivalent mks units.

        Example
        -------
        >>> from unyt import g, cm
        >>> (g/cm**3).get_mks_equivalent()
        kg/m**3
        """
        return self.get_base_equivalent(unit_system="mks")

    def get_conversion_factor(self, other_units, dtype=None):
        """Get the conversion factor and offset (if any) from one unit
        to another

        Parameters
        ----------
        other_units: unit object
           The units we want the conversion factor for
        dtype: numpy dtype
           The dtype to return the conversion factor as

        Returns
        -------
        conversion_factor : float
            old_units / new_units
        offset : float or None
            Offset between this unit and the other unit. None if there is
            no offset.

        Examples
        --------
        >>> from unyt import km, cm, degree_fahrenheit, degree_celsius
        >>> km.get_conversion_factor(cm)
        (100000.0, None)
        >>> degree_celsius.get_conversion_factor(degree_fahrenheit)
        (1.7999999999999998, -31.999999999999886)
        """
        return _get_conversion_factor(self, other_units, dtype)

    def latex_representation(self):
        """A LaTeX representation for the unit

        Examples
        --------
        >>> from unyt import g, cm
        >>> (g/cm**3).latex_representation()
        '\\\\frac{\\\\rm{g}}{\\\\rm{cm}^{3}}'
        """
        return self.latex_repr

    def as_coeff_unit(self):
        """Factor the coefficient multiplying a unit

        For units that are multiplied by a constant dimensionless
        coefficient, returns a tuple containing the coefficient and
        a new unit object for the unmultiplied unit.

        Example
        -------

        >>> import unyt as u
        >>> unit = (u.m**2/u.cm).simplify()
        >>> unit
        100*m
        >>> unit.as_coeff_unit()
        (100.0, m)
        """
        coeff, mul = self.expr.as_coeff_Mul()
        coeff = float(coeff)
        ret = Unit(
            mul,
            self.base_value / coeff,
            self.base_offset,
            self.dimensions,
            self.registry,
        )
        return coeff, ret

    def simplify(self):
        """Return a new equivalent unit object with a simplified unit expression

        >>> import unyt as u
        >>> unit = (u.m**2/u.cm).simplify()
        >>> unit
        100*m
        """
        expr = self.expr
        self.expr = _cancel_mul(expr, self.registry)
        return self


def _factor_pairs(expr):
    factors = expr.as_ordered_factors()
    expanded_factors = []
    for f in factors:
        if f.is_Number:
            continue
        base, exp = f.as_base_exp()
        if exp.q != 1:
            expanded_factors.append(base ** Mod(exp, 1))
            exp = floor(exp)
        if exp >= 0:
            f = (base,) * exp
        else:
            f = (1 / base,) * abs(exp)
        expanded_factors.extend(f)
    return list(itertools.combinations(expanded_factors, 2))


def _create_unit_from_factor(factor, registry):
    base, exp = factor.as_base_exp()
    f = registry[str(base)]
    return Unit(base, f[0], f[2], f[1], registry, f[3]) ** exp


def _cancel_mul(expr, registry):
    pairs_to_consider = _factor_pairs(expr)
    uncancelable_pairs = set()
    while len(pairs_to_consider):
        pair = pairs_to_consider.pop()
        if pair in uncancelable_pairs:
            continue
        u1 = _create_unit_from_factor(pair[0], registry)
        u2 = _create_unit_from_factor(pair[1], registry)
        prod = u1 * u2
        if prod.dimensions == 1:
            expr = expr / pair[0]
            expr = expr / pair[1]
            value = prod.base_value
            if value != 1:
                if value.is_integer():
                    value = int(value)
                expr *= value
        else:
            uncancelable_pairs.add(pair)
        pairs_to_consider = _factor_pairs(expr)
    return expr


#
# Unit manipulation functions
#


# map from dimensions in one unit system to dimensions in other system,
# canonical unit to convert to in that system, and floating point
# conversion factor
em_conversions = {
    ("C", dims.charge_mks): (dims.charge_cgs, "statC", 0.1 * speed_of_light_cm_per_s),
    ("statC", dims.charge_cgs): (dims.charge_mks, "C", 10.0 / speed_of_light_cm_per_s),
    ("T", dims.magnetic_field_mks): (dims.magnetic_field_cgs, "G", 1.0e4),
    ("G", dims.magnetic_field_cgs): (dims.magnetic_field_mks, "T", 1.0e-4),
    ("A", dims.current_mks): (dims.current_cgs, "statA", 0.1 * speed_of_light_cm_per_s),
    ("statA", dims.current_cgs): (
        dims.current_mks,
        "A",
        10.0 / speed_of_light_cm_per_s,
    ),
    ("V", dims.electric_potential_mks): (
        dims.electric_potential_cgs,
        "statV",
        1.0e-8 * speed_of_light_cm_per_s,
    ),
    ("statV", dims.electric_potential_cgs): (
        dims.electric_potential_mks,
        "V",
        1.0e8 / speed_of_light_cm_per_s,
    ),
    ("Ω", dims.resistance_mks): (
        dims.resistance_cgs,
        "statohm",
        1.0e9 / (speed_of_light_cm_per_s ** 2),
    ),
    ("statohm", dims.resistance_cgs): (
        dims.resistance_mks,
        "Ω",
        1.0e-9 * speed_of_light_cm_per_s ** 2,
    ),
}

em_conversion_dims = [k[1] for k in em_conversions.keys()]


def _em_conversion(orig_units, conv_data, to_units=None, unit_system=None):
    """Convert between E&M & MKS base units.

    If orig_units is a CGS (or MKS) E&M unit, conv_data contains the
    corresponding MKS (or CGS) unit and scale factor converting between them.
    This must be done by replacing the expression of the original unit
    with the new one in the unit expression and multiplying by the scale
    factor.
    """
    conv_unit, canonical_unit, scale = conv_data
    if conv_unit is None:
        conv_unit = canonical_unit
    new_expr = scale * canonical_unit.expr
    if unit_system is not None:
        # we don't know the to_units, so we get it directly from the
        # conv_data
        to_units = Unit(conv_unit.expr, registry=orig_units.registry)
    new_units = Unit(new_expr, registry=orig_units.registry)
    conv = new_units.get_conversion_factor(to_units)
    return to_units, conv


@lru_cache(maxsize=128, typed=False)
def _check_em_conversion(unit, to_unit=None, unit_system=None, registry=None):
    """Check to see if the units contain E&M units

    This function supports unyt's ability to convert data to and from E&M
    electromagnetic units. However, this support is limited and only very
    simple unit expressions can be readily converted. This function tries
    to see if the unit is an atomic base unit that is present in the
    em_conversions dict. If it does not contain E&M units, the function
    returns an empty tuple. If it does contain an atomic E&M unit in
    the em_conversions dict, it returns a tuple containing the unit to convert
    to and scale factor. If it contains a more complicated E&M unit and we are
    trying to convert between CGS & MKS E&M units, it raises an error.
    """
    em_map = ()
    if unit == to_unit or unit.dimensions not in em_conversion_dims:
        return em_map
    if unit.is_atomic:
        prefix, unit_wo_prefix = _split_prefix(str(unit), unit.registry.lut)
    else:
        prefix, unit_wo_prefix = "", str(unit)
    if (unit_wo_prefix, unit.dimensions) in em_conversions:
        em_info = em_conversions[unit_wo_prefix, unit.dimensions]
        em_unit = Unit(prefix + em_info[1], registry=registry)
        if to_unit is None:
            cmks_in_unit = current_mks in unit.dimensions.atoms()
            cmks_in_unit_system = unit_system.units_map[current_mks]
            cmks_in_unit_system = cmks_in_unit_system is not None
            if cmks_in_unit and cmks_in_unit_system:
                em_map = (unit_system[unit.dimensions], unit, 1.0)
            else:
                em_map = (None, em_unit, em_info[2])
        elif to_unit.dimensions == em_unit.dimensions:
            em_map = (to_unit, em_unit, em_info[2])
    if em_map:
        return em_map
    if unit_system is None:
        from unyt.unit_systems import unit_system_registry

        unit_system = unit_system_registry["mks"]
    for unit_atom in unit.expr.atoms():
        if unit_atom.is_Number:
            continue
        bu = str(unit_atom)
        budims = Unit(bu, registry=registry).dimensions
        try:
            if str(unit_system[budims]) == bu:
                continue
        except MissingMKSCurrent:
            raise MKSCGSConversionError(unit)
    return em_map


def _get_conversion_factor(old_units, new_units, dtype):
    """
    Get the conversion factor between two units of equivalent dimensions. This
    is the number you multiply data by to convert from values in `old_units` to
    values in `new_units`.

    Parameters
    ----------
    old_units: str or Unit object
        The current units.
    new_units : str or Unit object
        The units we want.
    dtype: NumPy dtype
        The dtype of the conversion factor

    Returns
    -------
    conversion_factor : float
        `old_units / new_units`
    offset : float or None
        Offset between the old unit and new unit.

    """
    if old_units.dimensions != new_units.dimensions:
        raise UnitConversionError(
            old_units, old_units.dimensions, new_units, new_units.dimensions
        )
    ratio = old_units.base_value / new_units.base_value
    if old_units.base_offset == 0 and new_units.base_offset == 0:
        return (ratio, None)
    else:
        # the dimensions are the same, so both are temperatures, where
        # it's legal to convert units so no need to do error checking
        return ratio, ratio * old_units.base_offset - new_units.base_offset


#
# Helper functions
#


def _get_unit_data_from_expr(unit_expr, unit_symbol_lut):
    """
    Grabs the total base_value and dimensions from a valid unit expression.

    Parameters
    ----------
    unit_expr: Unit object, or sympy Expr object
        The expression containing unit symbols.
    unit_symbol_lut: dict
        Provides the unit data for each valid unit symbol.

    """
    # Now for the sympy possibilities
    if isinstance(unit_expr, Number):
        if unit_expr is sympy_one:
            return (1.0, sympy_one)
        return (float(unit_expr), sympy_one)

    if isinstance(unit_expr, Symbol):
        return _lookup_unit_symbol(unit_expr.name, unit_symbol_lut)

    if isinstance(unit_expr, Pow):
        unit_data = _get_unit_data_from_expr(unit_expr.args[0], unit_symbol_lut)
        power = unit_expr.args[1]
        if isinstance(power, Symbol):
            raise UnitParseError("Invalid unit expression '%s'." % unit_expr)
        conv = float(unit_data[0] ** power)
        unit = unit_data[1] ** power
        return (conv, unit)

    if isinstance(unit_expr, Mul):
        base_value = 1.0
        dimensions = 1
        for expr in unit_expr.args:
            unit_data = _get_unit_data_from_expr(expr, unit_symbol_lut)
            base_value *= unit_data[0]
            dimensions *= unit_data[1]

        return (float(base_value), dimensions)

    raise UnitParseError(
        "Cannot parse for unit data from '%s'. Please supply"
        " an expression of only Unit, Symbol, Pow, and Mul"
        "objects." % str(unit_expr)
    )


def _validate_dimensions(dimensions):
    if isinstance(dimensions, Mul):
        for dim in dimensions.args:
            _validate_dimensions(dim)
    elif isinstance(dimensions, Symbol):
        if dimensions not in base_dimensions:
            raise UnitParseError(
                "Dimensionality expression contains an "
                "unknown symbol '%s'." % dimensions
            )
    elif isinstance(dimensions, Pow):
        if not isinstance(dimensions.args[1], Number):
            raise UnitParseError(
                "Dimensionality expression '%s' contains a "
                "unit symbol as a power." % dimensions
            )
    elif isinstance(dimensions, (Add, Number)):
        if not isinstance(dimensions, One):
            raise UnitParseError(
                "Only dimensions that are instances of Pow, "
                "Mul, or symbols in the base dimensions are "
                "allowed.  Got dimensions '%s'" % dimensions
            )
    elif not isinstance(dimensions, Basic):
        raise UnitParseError("Bad dimensionality expression '%s'." % dimensions)


def define_unit(
    symbol, value, tex_repr=None, offset=None, prefixable=False, registry=None
):
    """
    Define a new unit and add it to the specified unit registry.

    Parameters
    ----------
    symbol : string
        The symbol for the new unit.
    value : tuple or :class:`unyt.array.unyt_quantity`
        The definition of the new unit in terms of some other units. For
        example, one would define a new "mph" unit with ``(1.0, "mile/hr")``
        or with ``1.0*unyt.mile/unyt.hr``
    tex_repr : string, optional
        The LaTeX representation of the new unit. If one is not supplied, it
        will be generated automatically based on the symbol string.
    offset : float, optional
        The default offset for the unit. If not set, an offset of 0 is assumed.
    prefixable : boolean, optional
        Whether or not the new unit can use SI prefixes. Default: False
    registry : :class:`unyt.unit_registry.UnitRegistry` or None
        The unit registry to add the unit to. If None, then defaults to the
        global default unit registry. If registry is set to None then the
        unit object will be added as an attribute to the top-level :mod:`unyt`
        namespace to ease working with the newly defined unit. See the example
        below.

    Examples
    --------
    >>> from unyt import day
    >>> two_weeks = 14.0*day
    >>> one_day = 1.0*day
    >>> define_unit("two_weeks", two_weeks)
    >>> from unyt import two_weeks
    >>> print((3*two_weeks)/one_day)
    42.0 dimensionless
    """
    from unyt.array import unyt_quantity, _iterable
    import unyt

    if registry is None:
        registry = default_unit_registry
    if symbol in registry:
        raise RuntimeError(
            "Unit symbol '%s' already exists in the provided " "registry" % symbol
        )
    if not isinstance(value, unyt_quantity):
        if _iterable(value) and len(value) == 2:
            value = unyt_quantity(value[0], value[1], registry=registry)
        else:
            raise RuntimeError(
                '"value" needs to be a quantity or ' "(value, unit) tuple!"
            )
    base_value = float(value.in_base(unit_system="mks"))
    dimensions = value.units.dimensions
    registry.add(
        symbol,
        base_value,
        dimensions,
        prefixable=prefixable,
        tex_repr=tex_repr,
        offset=offset,
    )
    if registry is default_unit_registry:
        u = Unit(symbol, registry=registry)
        setattr(unyt, symbol, u)


NULL_UNIT = Unit()
