"""
Equivalencies between different kinds of units

"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------

from __future__ import division

from collections import OrderedDict

from unyt.dimensions import (
    temperature,
    mass,
    energy,
    length,
    rate,
    velocity,
    dimensionless,
    density,
    number_density,
    flux,
    spatial_frequency,
)
from unyt.exceptions import InvalidUnitEquivalence

import numpy as np

equivalence_registry = OrderedDict()


class _RegisteredEquivalence(type):
    def __init__(cls, name, b, d):
        type.__init__(cls, name, b, d)
        if hasattr(cls, "type_name"):
            equivalence_registry[cls.type_name] = cls


class Equivalence(object, metaclass=_RegisteredEquivalence):
    def __init__(self, in_place=False):
        self.in_place = in_place

    def convert(self, x, new_dims, **kwargs):
        if x.units.dimensions in self._dims and new_dims in self._dims:
            return self._convert(x, new_dims, **kwargs)
        else:
            raise InvalidUnitEquivalence(self, x.units, new_dims)

    def _get_out(self, x):
        if self.in_place:
            return x
        return None


class NumberDensityEquivalence(Equivalence):
    """Equivalence between mass and number density, given a mean molecular
    weight.

    Given a number density :math:`n`, the mass density :math:`\\rho` is:

    .. math::

      \\rho = \\mu m_{\\rm H} n

    And similarly

    .. math::

      n = \\rho (\\mu m_{\\rm H})^{-1}

    Parameters
    ----------
    mu : float
      The mean molecular weight. Defaults to 0.6 whcih is valid for fully
      ionized gas with primordial composition.

    Example
    -------
    >>> print(NumberDensityEquivalence())
    number density: density <-> number density
    >>> from unyt import Msun, pc
    >>> rho = 3*Msun/pc**3
    >>> rho.to_equivalent('cm**-3', 'number_density', mu=1.4)
    unyt_quantity(86.64869896, 'cm**(-3)')
    """

    type_name = "number_density"
    _dims = (density, number_density)

    def _convert(self, x, new_dims, mu=0.6):
        from unyt import physical_constants as pc

        if new_dims == number_density:
            return np.true_divide(x, mu * pc.mh, out=self._get_out(x))
        elif new_dims == density:
            return np.multiply(x, mu * pc.mh, out=self._get_out(x))

    def __str__(self):
        return "number density: density <-> number density"


class ThermalEquivalence(Equivalence):
    """Equivalence between temperature and energy via the Boltzmann constant

    Given a temperature :math:`T` in an absolute scale (e.g. Kelvin or
    Rankine), the equivalent thermal energy :math:`E` for that temperature is
    given by:

    .. math::

      E = k_B T

    And

    .. math::

      T = E/k_B

    Where :math:`k_B` is Boltzmann's constant.

    Example
    -------
    >>> print(ThermalEquivalence())
    thermal: temperature <-> energy
    >>> from unyt import Kelvin
    >>> temp = 1e6*Kelvin
    >>> temp.to_equivalent('keV', 'thermal')
    unyt_quantity(0.08617332, 'keV')
    """

    type_name = "thermal"
    _dims = (temperature, energy)

    def _convert(self, x, new_dims):
        from unyt import physical_constants as pc

        if new_dims == energy:
            return np.multiply(x, pc.kboltz, out=self._get_out(x))
        elif new_dims == temperature:
            return np.true_divide(x, pc.kboltz, out=self._get_out(x))

    def __str__(self):
        return "thermal: temperature <-> energy"


class MassEnergyEquivalence(Equivalence):
    """Equivalence between mass and energy in special relativity

    Given a body with mass :math:`m`, the self-energy :math:`E` of that mass is
    given by

    .. math::

      E = m c^2

    where :math:`c` is the speed of light.

    Example
    -------
    >>> print(MassEnergyEquivalence())
    mass_energy: mass <-> energy
    >>> from unyt import g
    >>> (3.5*g).to_equivalent('J', 'mass_energy')
    unyt_quantity(3.14564313e+14, 'J')

    """

    type_name = "mass_energy"
    _dims = (mass, energy)

    def _convert(self, x, new_dims):
        from unyt import physical_constants as pc

        if new_dims == energy:
            return np.multiply(x, pc.clight * pc.clight, out=self._get_out(x))
        elif new_dims == mass:
            return np.true_divide(x, pc.clight * pc.clight, out=self._get_out(x))

    def __str__(self):
        return "mass_energy: mass <-> energy"


class SpectralEquivalence(Equivalence):
    """Equivalence between wavelength, frequency, and energy of a photon.

    Given a photon with wavelength :math:`\\lambda`, spatial frequency
    :math:`\\bar\\nu`, frequency :math:`\\nu` and Energy :math:`E`,
    these quantities are related by the following forumlae:

    .. math::

      E = h \\nu = h c / \\lambda = h c \\bar\\nu

    where :math:`h` is Planck's constant and :math:`c` is the speed of light.

    Example
    ------
    >>> print(SpectralEquivalence())
    spectral: length <-> spatial_frequency <-> frequency <-> energy
    >>> from unyt import angstrom, km
    >>> (3*angstrom).to_equivalent('keV', 'spectral')
    unyt_quantity(4.13280644, 'keV')
    >>> (1*km).to_equivalent('MHz', 'spectral')
    unyt_quantity(0.29979246, 'MHz')
    """

    type_name = "spectral"
    _dims = (length, rate, energy, spatial_frequency)

    def _convert(self, x, new_dims):
        from unyt import physical_constants as pc

        if new_dims == energy:
            if x.units.dimensions == length:
                return np.true_divide(pc.clight * pc.h_mks, x, out=self._get_out(x))
            elif x.units.dimensions == rate:
                return np.multiply(x, pc.h_mks, out=self._get_out(x))
            elif x.units.dimensions == spatial_frequency:
                return np.multiply(x, pc.h_mks * pc.clight, out=self._get_out(x))
        elif new_dims == length:
            if x.units.dimensions == rate:
                return np.true_divide(pc.clight, x, out=self._get_out(x))
            elif x.units.dimensions == energy:
                return np.true_divide(pc.h_mks * pc.clight, x, out=self._get_out(x))
            elif x.units.dimensions == spatial_frequency:
                return np.true_divide(1, x, out=self._get_out(x))
        elif new_dims == rate:
            if x.units.dimensions == length:
                return np.true_divide(pc.clight, x, out=self._get_out(x))
            elif x.units.dimensions == energy:
                return np.true_divide(x, pc.h_mks, out=self._get_out(x))
            elif x.units.dimensions == spatial_frequency:
                return np.multiply(x, pc.clight, out=self._get_out(x))
        elif new_dims == spatial_frequency:
            if x.units.dimensions == length:
                return np.true_divide(1, x, out=self._get_out(x))
            elif x.units.dimensions == energy:
                return np.true_divide(x, pc.clight * pc.h_mks, out=self._get_out(x))
            elif x.units.dimensions == rate:
                return np.true_divide(x, pc.clight, out=self._get_out(x))

    def __str__(self):
        return "spectral: length <-> spatial_frequency <-> frequency " + "<-> energy"


class SoundSpeedEquivalence(Equivalence):
    """Equivalence between the sound speed, temperature, and thermal energy of
    an ideal gas

    For an ideal gas with sound speed :math:`c_s`, temperature :math:`T`, and
    thermal energy :math:`E`, the following equalities will hold:

    .. math::

      c_s = \\sqrt{\\frac{\\gamma k_B T}{\\mu m_{\\rm H}}}

    and

    .. math::

      E = c_s^2 \\mu m_{\\rm H} / \\gamma = k_B T

    where :math:`k_B` is Boltzmann's constant, :math:`\\mu` is the mean
    molecular weight of the gas, and :math:`\\gamma` is the ratio of specific
    heats.

    Parameters
    ----------
    gamma : float
       The ratio of specific heats. Defaults to 5/3, which is correct for
       monatomic species.
    mu : float
       The mean molecular weight. Defaults to 0.6, which is valid for fully
       ionized gas with primordial composition.

    Example
    -------
    >>> print(SoundSpeedEquivalence())
    sound_speed (ideal gas): velocity <-> temperature <-> energy
    >>> from unyt import Kelvin, km, s
    >>> hot = 1e6*Kelvin
    >>> hot.to_equivalent('km/s', 'sound_speed')
    unyt_quantity(151.37249927, 'km/s')
    >>> hot.to_equivalent('keV', 'sound_speed')
    unyt_quantity(0.08617332, 'keV')
    >>> cs = 100*km/s
    >>> cs.to_equivalent('K', 'sound_speed')
    unyt_quantity(436421.39881617, 'K')
    >>> cs.to_equivalent('keV', 'sound_speed')
    unyt_quantity(0.03760788, 'keV')
    """

    type_name = "sound_speed"
    _dims = (velocity, temperature, energy)

    def _convert(self, x, new_dims, mu=0.6, gamma=5.0 / 3.0):
        from unyt import physical_constants as pc

        if new_dims == velocity:
            if x.units.dimensions == temperature:
                v2 = np.multiply(
                    pc.kboltz * gamma / (mu * pc.mh), x, out=self._get_out(x)
                )
            elif x.units.dimensions == energy:
                v2 = np.multiply(gamma / (mu * pc.mh), x, out=self._get_out(x))
            return np.sqrt(v2, out=self._get_out(x))
        elif new_dims == temperature:
            if x.units.dimensions == velocity:
                v2 = np.multiply(x, x, out=self._get_out(x))
                kT = np.multiply(v2, mu * pc.mh / gamma, out=self._get_out(x))
                return np.true_divide(kT, pc.kboltz, out=self._get_out(x))
            else:
                return np.true_divide(x, pc.kboltz, out=self._get_out(x))
        else:
            if x.units.dimensions == velocity:
                v2 = np.multiply(x, x, out=self._get_out(x))
                return np.multiply(mu * pc.mh / gamma, v2, out=self._get_out(x))
            else:
                return np.multiply(x, pc.kboltz, out=self._get_out(x))

    def __str__(self):
        return "sound_speed (ideal gas): velocity <-> temperature <-> energy"


class LorentzEquivalence(Equivalence):
    """Equivalence between velocity and the Lorentz gamma factor.

    For a body with velocity :math:`v`, the Lorentz gamma factor,
    :math:`\\gamma` is

    .. math::

      \\gamma = \\frac{1}{\\sqrt{1 - v^2/c^2}}

    ans similarly

    .. math::

      v = \\frac{c}{\\sqrt{1 - \\gamma^2}}

    where :math:`c` is the speed of light.

    Example
    -------
    >>> print(LorentzEquivalence())
    lorentz: velocity <-> dimensionless
    >>> from unyt import c, dimensionless
    >>> v = 0.99*c
    >>> print(v.to_equivalent('', 'lorentz'))
    7.088812050083393 dimensionless
    >>> fast = 99.9*dimensionless
    >>> fast.to_equivalent('c', 'lorentz')
    unyt_quantity(0.9999499, 'c')
    >>> fast.to_equivalent('km/s', 'lorentz')
    unyt_quantity(299777.43797656, 'km/s')
    """

    type_name = "lorentz"
    _dims = (dimensionless, velocity)

    def _convert(self, x, new_dims):
        from unyt import physical_constants as pc

        if new_dims == dimensionless:
            beta = np.true_divide(x, pc.clight, out=self._get_out(x))
            beta2 = np.multiply(beta, beta, out=self._get_out(x))
            inv_gamma_2 = np.subtract(1, beta2, out=self._get_out(x))
            inv_gamma = np.sqrt(inv_gamma_2, out=self._get_out(x))
            gamma = np.true_divide(1.0, inv_gamma, out=self._get_out(x))
            return gamma
        elif new_dims == velocity:
            gamma2 = np.multiply(x, x, out=self._get_out(x))
            inv_gamma_2 = np.true_divide(1, gamma2, out=self._get_out(x))
            beta2 = np.subtract(1, inv_gamma_2, out=self._get_out(x))
            beta = np.sqrt(beta2, out=self._get_out(x))
            return np.multiply(pc.clight, beta, out=self._get_out(x))

    def __str__(self):
        return "lorentz: velocity <-> dimensionless"


class SchwarzschildEquivalence(Equivalence):
    """Equivalence between the mass and radius of a Schwarzschild black hole

    A Schwarzschild black hole of mass :math:`M` has radius :math:`R`

    .. math::

      R = \\frac{2 G M}{c^2}

    and similarly

    .. math::

      M = \\frac{R c^2}{2 G}

    where :math:`G` is Newton's gravitational constant and :math:`c` is the
    speed of light.

    Example
    -------
    >>> print(SchwarzschildEquivalence())
    schwarzschild: mass <-> length
    >>> from unyt import Msun, AU
    >>> (10*Msun).to_equivalent('km', 'schwarzschild')
    unyt_quantity(29.53161626, 'km')
    >>> (1*AU).to_equivalent('Msun', 'schwarzschild')
    unyt_quantity(50656851.7815179, 'Msun')
    """

    type_name = "schwarzschild"
    _dims = (mass, length)

    def _convert(self, x, new_dims):
        from unyt import physical_constants as pc

        if new_dims == length:
            return np.multiply(
                2.0 * pc.G / (pc.clight * pc.clight), x, out=self._get_out(x)
            )
        elif new_dims == mass:
            return np.multiply(
                0.5 * pc.clight * pc.clight / pc.G, x, out=self._get_out(x)
            )

    def __str__(self):
        return "schwarzschild: mass <-> length"


class ComptonEquivalence(Equivalence):
    """Equivalence between the Compton wavelength
    of a particle and its mass.

    .. math::

      \\lambda_c = h/mc

    Example
    -------
    >>> print(ComptonEquivalence())
    compton: mass <-> length
    >>> from unyt import me, fm
    >>> me.to_equivalent('angstrom', 'compton')
    unyt_quantity(0.0242631, 'Å')
    >>> (10*fm).to_equivalent('me', 'compton')
    unyt_quantity(242.63102371, 'me')
    """

    type_name = "compton"
    _dims = (mass, length)

    def _convert(self, x, new_dims):
        from unyt import physical_constants as pc

        return np.true_divide(pc.h_mks / pc.clight, x, out=self._get_out(x))

    def __str__(self):
        return "compton: mass <-> length"


class EffectiveTemperatureEquivalence(Equivalence):
    """Equivalence between the emmitted flux accross all wavelengths and
    temperature of a blackbody

    For a blackbody emitter with Temperature :math:`T` emitting radiation with
    a flux :math:`F`, the following equality holds:

    .. math::

    F = \\sigma T^4

    where :math:`\\sigma` is the Stefan-Boltzmann constant.

    Example
    -------
    >>> print(EffectiveTemperatureEquivalence())
    effective_temperature: flux <-> temperature
    >>> from unyt import K, W, m
    >>> (5000.*K).to_equivalent('W/m**2', 'effective_temperature')
    unyt_quantity(35439831.25, 'W/m**2')
    >>> (100.*W/m**2).to_equivalent('K', 'effective_temperature')
    unyt_quantity(204.92601414, 'K')
    """

    type_name = "effective_temperature"
    _dims = (flux, temperature)

    def _convert(self, x, new_dims):
        from unyt import physical_constants as pc

        if new_dims == flux:
            x4 = np.power(x, 4, out=self._get_out(x))
            return np.multiply(
                pc.stefan_boltzmann_constant_mks, x4, out=self._get_out(x)
            )
        elif new_dims == temperature:
            T4 = np.true_divide(
                x, pc.stefan_boltzmann_constant_mks, out=self._get_out(x)
            )
            ret = np.power(T4, 0.25, out=self._get_out(x))
            return ret

    def __str__(self):
        return "effective_temperature: flux <-> temperature"
