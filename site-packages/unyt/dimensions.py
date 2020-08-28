"""
Dimensions of physical quantities


"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------


from itertools import chain

from sympy import Symbol, sympify, Rational
from functools import wraps

#: mass
mass = Symbol("(mass)", positive=True)
#: length
length = Symbol("(length)", positive=True)
#: time
time = Symbol("(time)", positive=True)
#: temperature
temperature = Symbol("(temperature)", positive=True)
#: angle
angle = Symbol("(angle)", positive=True)
#: current_mks
current_mks = Symbol("(current_mks)", positive=True)
#: luminous_intensity
luminous_intensity = Symbol("(luminous_intensity)", positive=True)
#: dimensionless
dimensionless = sympify(1)
#: logarithmic
logarithmic = Symbol("(logarithmic)", positive=True)

#: A list of all of the base dimensions
base_dimensions = [
    mass,
    length,
    time,
    temperature,
    angle,
    current_mks,
    dimensionless,
    luminous_intensity,
    logarithmic,
]

#
# Derived dimensions
#

# rate
rate = 1 / time
# frequency (alias for rate)
frequency = rate

# spatial frequency
spatial_frequency = 1 / length

#: solid_angle
solid_angle = angle * angle
#: velocity
velocity = length / time
#: acceleration
acceleration = length / time ** 2
#: jerk
jerk = length / time ** 3
#: snap
snap = length / time ** 4
#: crackle
crackle = length / time ** 5
#: pop
pop = length / time ** 6

#: area
area = length * length
#: volume
volume = area * length
#: momentum
momentum = mass * velocity
#: force
force = mass * acceleration
#: pressure
pressure = force / area
#: energy
energy = force * length
#: power
power = energy / time
#: flux
flux = power / area
#: specific_flux
specific_flux = flux / rate
#: number_density
number_density = 1 / (length * length * length)
#: density
density = mass * number_density
#: angular_momentum
angular_momentum = mass * length * velocity
#: specific_angular_momentum
specific_angular_momentum = angular_momentum / mass
#: specific_energy
specific_energy = energy / mass
#: count_flux
count_flux = 1 / (area * time)
#: count_intensity
count_intensity = count_flux / solid_angle
#: luminous_flux
luminous_flux = luminous_intensity * solid_angle
#: luminance
luminance = luminous_intensity / area

# Gaussian electromagnetic units
#: charge_cgs
charge_cgs = (energy * length) ** Rational(1, 2)  # proper 1/2 power
#: current_cgs
current_cgs = charge_cgs / time
#: electric_field_cgs
electric_field_cgs = charge_cgs / length ** 2
#: magnetic_field_cgs
magnetic_field_cgs = electric_field_cgs
#: electric_potential_cgs
electric_potential_cgs = energy / charge_cgs
#: resistance_cgs
resistance_cgs = electric_potential_cgs / current_cgs
#: magnetic_flux_cgs
magnetic_flux_cgs = magnetic_field_cgs * area

# SI electromagnetic units
#: charge
charge = charge_mks = current_mks * time
#: electric_field
electric_field = electric_field_mks = force / charge_mks
#: magnetic_field
magnetic_field = magnetic_field_mks = electric_field_mks / velocity
#: electric_potential
electric_potential = electric_potential_mks = energy / charge_mks
#: resistance
resistance = resistance_mks = electric_potential_mks / current_mks
#: capacitance
capacitance = capacitance_mks = charge / electric_potential
#: magnetic_flux
magnetic_flux = magnetic_flux_mks = magnetic_field_mks * area
#: inductance
inductance = inductance_mks = magnetic_flux_mks / current_mks

#: a list containing all derived_dimensions
derived_dimensions = [
    rate,
    velocity,
    acceleration,
    jerk,
    snap,
    crackle,
    pop,
    momentum,
    force,
    energy,
    power,
    charge_cgs,
    electric_field_cgs,
    magnetic_field_cgs,
    solid_angle,
    flux,
    specific_flux,
    volume,
    luminous_flux,
    area,
    current_cgs,
    charge_mks,
    electric_field_mks,
    magnetic_field_mks,
    electric_potential_cgs,
    electric_potential_mks,
    resistance_cgs,
    resistance_mks,
    magnetic_flux_mks,
    magnetic_flux_cgs,
    luminance,
    spatial_frequency,
]


#: a list containing all dimensions
dimensions = base_dimensions + derived_dimensions

#: a dict containing a bidirectional mapping from
#: mks dimension to cgs dimension
em_dimensions = {
    magnetic_field_mks: magnetic_field_cgs,
    magnetic_flux_mks: magnetic_flux_cgs,
    charge_mks: charge_cgs,
    current_mks: current_cgs,
    electric_potential_mks: electric_potential_cgs,
    resistance_mks: resistance_cgs,
}

for k, v in list(em_dimensions.items()):
    em_dimensions[v] = k


def accepts(**arg_units):
    """Decorator for checking units of function arguments.

    Parameters
    ----------
    arg_units: dict
        Mapping of function arguments to dimensions, of the form 'arg1'=dimension1 etc
        where ``'arg1'`` etc are the function arguments and ``dimension1`` etc
        are SI base units (or combination of units), eg. length/time.

    Notes
    -----
    Keyword args are not dimensionally check, being directly passed to the
    decorated function.

    Function arguments that don't have attached units can be skipped can bypass
    dimensionality checking by not being passed to the decorator. See ``baz`` in
    the examples, where ``a`` has no units.

    Examples
    --------
    >>> import unyt as u
    >>> from unyt.dimensions import length, time
    >>> @accepts(a=time, v=length/time)
    ... def foo(a, v):
    ...     return a * v
    ...
    >>> res = foo(a= 2 * u.s, v = 3 * u.m/u.s)
    >>> print(res)
    6 m
    >>> @accepts(a=length, v=length/time)
    ... def bar(a, v):
    ...     return a * v
    ...
    >>> bar(a= 2 * u.s, v = 3 * u.m/u.s)
    Traceback (most recent call last):
    ...
    TypeError: arg 'a=2 s' does not match (length)
    >>> @accepts(v=length/time)
    ... def baz(a, v):
    ...     return a * v
    ...
    >>> res = baz(a= 2, v = 3 * u.m/u.s)
    >>> print(res)
    6 m/s

    """

    def check_accepts(f):
        """Decorates original function.

        Parameters
        ----------
        f : function
            Function being decorated.

        Returns
        -------
        new_f: function
            Decorated function.

        """
        names_of_args = f.__code__.co_varnames

        @wraps(f)
        def new_f(*args, **kwargs):
            """The new function being returned from the decorator.

            Check units of `args` and `kwargs`, then run original function.

            Raises
            ------
            TypeError
                If the units do not match.

            """
            for arg_name, arg_value in chain(zip(names_of_args, args), kwargs.items()):
                if arg_name in arg_units:  # function argument needs to be checked
                    dimension = arg_units[arg_name]
                    if not _has_dimensions(arg_value, dimension):
                        raise TypeError(
                            "arg '%s=%s' does not match %s"
                            % (arg_name, arg_value, dimension)
                        )
            return f(*args, **kwargs)

        return new_f

    return check_accepts


def returns(r_unit):
    """Decorator for checking function return units.

    Parameters
    ----------
    r_unit: :py:class:`sympy.core.symbol.Symbol`
        SI base unit (or combination of units), eg. length/time
        of the value returned by the original function

    Examples
    --------
    >>> import unyt as u
    >>> from unyt.dimensions import length, time
    >>> @returns(length)
    ... def f(a, v):
    ...     return a * v
    ...
    >>> res = f(a= 2 * u.s, v = 3 * u.m/u.s)
    >>> print(res)
    6 m
    >>> @returns(length/time)
    ... def f(a, v):
    ...     return a * v
    ...
    >>> f(a= 2 * u.s, v = 3 * u.m/u.s)
    Traceback (most recent call last):
    ...
    TypeError: result '6 m' does not match (length)/(time)

    """

    def check_returns(f):
        """Decorates original function.

        Parameters
        ----------
        f : function
            Function being decorated.

        Returns
        -------
        new_f: function
            Decorated function.

        """

        @wraps(f)
        def new_f(*args, **kwargs):
            """The decorated function, which checks the return unit.

            Raises
            ------
            TypeError
                If the units do not match.

            """
            result = f(*args, **kwargs)
            if not _has_dimensions(result, r_unit):
                raise TypeError("result '%s' does not match %s" % (result, r_unit))
            return result

        return new_f

    return check_returns


def _has_dimensions(quant, dim):
    """Checks the argument has the right dimensionality.

    Parameters
    ----------
    quant : :py:class:`unyt.array.unyt_quantity`
        Quantity whose dimensionality we want to check.
    dim : :py:class:`sympy.core.symbol.Symbol`
        SI base unit (or combination of units), eg. length/time

    Returns
    -------
    bool
        True if check successful.

    Examples
    --------
    >>> import unyt as u
    >>> from unyt.dimensions import length, time
    >>> _has_dimensions(3 * u.m/u.s, length/time)
    True
    >>> _has_dimensions(3, length)
    False
    """
    try:
        arg_dim = quant.units.dimensions
    except AttributeError:
        arg_dim = dimensionless
    return arg_dim == dim
