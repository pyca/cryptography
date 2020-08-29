# -*- coding: utf-8 -*-
"""
The default unit symbol lookup table.


"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------

from collections import defaultdict, OrderedDict

from unyt import dimensions
from unyt._physical_ratios import (
    m_per_pc,
    m_per_ly,
    m_per_au,
    m_per_rsun,
    m_per_inch,
    m_per_ft,
    watt_per_horsepower,
    mass_sun_kg,
    mass_jupiter_kg,
    mass_earth_kg,
    mass_mercury_kg,
    mass_venus_kg,
    mass_mars_kg,
    mass_saturn_kg,
    mass_uranus_kg,
    mass_neptune_kg,
    sec_per_year,
    sec_per_day,
    sec_per_hr,
    sec_per_min,
    temp_sun_kelvin,
    luminosity_sun_watts,
    metallicity_sun,
    J_per_eV,
    amu_kg,
    amu_grams,
    mass_electron_kg,
    mass_hydrogen_kg,
    mass_proton_kg,
    m_per_ang,
    jansky_mks,
    kelvin_per_rankine,
    speed_of_light_m_per_s,
    planck_length_m,
    planck_charge_C,
    planck_energy_J,
    planck_mass_kg,
    planck_temperature_K,
    planck_time_s,
    kg_per_pound,
    pascal_per_atm,
    m_per_rearth,
    m_per_rjup,
    boltzmann_constant_J_per_K,
    standard_gravity_m_per_s2,
    newton_mks,
    planck_mks,
    eps_0,
    mu_0,
    avogadros_number,
    neper_per_bel,
)
import numpy as np

# Lookup a unit symbol with the symbol string, and provide a tuple with the
# conversion factor to cgs and dimensionality.

default_unit_symbol_lut = OrderedDict(
    [
        # base
        ("m", (1.0, dimensions.length, 0.0, r"\rm{m}", True)),
        ("g", (1.0e-3, dimensions.mass, 0.0, r"\rm{g}", True)),
        ("s", (1.0, dimensions.time, 0.0, r"\rm{s}", True)),
        ("K", (1.0, dimensions.temperature, 0.0, r"\rm{K}", True)),
        ("rad", (1.0, dimensions.angle, 0.0, r"\rm{rad}", True)),
        ("A", (1.0, dimensions.current_mks, 0.0, r"\rm{A}", True)),
        ("cd", (1.0, dimensions.luminous_intensity, 0.0, r"\rm{cd}", True)),
        ("mol", (1.0 / amu_grams, dimensions.dimensionless, 0.0, r"\rm{mol}", True)),
        # some cgs
        ("dyn", (1.0e-5, dimensions.force, 0.0, r"\rm{dyn}", True)),
        ("erg", (1.0e-7, dimensions.energy, 0.0, r"\rm{erg}", True)),
        ("Ba", (0.1, dimensions.pressure, 0.0, r"\rm{Ba}", True)),
        ("G", (0.1 ** 0.5, dimensions.magnetic_field_cgs, 0.0, r"\rm{G}", True)),
        ("statC", (1.0e-3 ** 1.5, dimensions.charge_cgs, 0.0, r"\rm{statC}", True)),
        ("statA", (1.0e-3 ** 1.5, dimensions.current_cgs, 0.0, r"\rm{statA}", True)),
        (
            "statV",
            (
                0.1 * 1.0e-3 ** 0.5,
                dimensions.electric_potential_cgs,
                0.0,
                r"\rm{statV}",
                True,
            ),
        ),
        ("statohm", (100.0, dimensions.resistance_cgs, 0.0, r"\rm{statohm}", True)),
        ("Mx", (1.0e-3 ** 1.5, dimensions.magnetic_flux_cgs, 0.0, r"\rm{Mx}", True)),
        # some SI
        ("J", (1.0, dimensions.energy, 0.0, r"\rm{J}", True)),
        ("W", (1.0, dimensions.power, 0.0, r"\rm{W}", True)),
        ("Hz", (1.0, dimensions.rate, 0.0, r"\rm{Hz}", True)),
        ("N", (1.0, dimensions.force, 0.0, r"\rm{N}", True)),
        ("C", (1.0, dimensions.charge_mks, 0.0, r"\rm{C}", True)),
        ("T", (1.0, dimensions.magnetic_field_mks, 0.0, r"\rm{T}", True)),
        ("Pa", (1.0, dimensions.pressure, 0.0, r"\rm{Pa}", True)),
        ("bar", (1.0e5, dimensions.pressure, 0.0, r"\rm{bar}", True)),
        ("V", (1.0, dimensions.electric_potential, 0.0, r"\rm{V}", True)),
        ("F", (1.0, dimensions.capacitance, 0.0, r"\rm{F}", True)),
        ("H", (1.0, dimensions.inductance, 0.0, r"\rm{H}", True)),
        ("Ω", (1.0, dimensions.resistance, 0.0, r"\Omega", True)),
        ("Wb", (1.0, dimensions.magnetic_flux, 0.0, r"\rm{Wb}", True)),
        ("lm", (1.0, dimensions.luminous_flux, 0.0, r"\rm{lm}", True)),
        (
            "lx",
            (1.0, dimensions.luminous_flux / dimensions.area, 0.0, r"\rm{lx}", True),
        ),
        ("degC", (1.0, dimensions.temperature, -273.15, r"^\circ\rm{C}", True)),
        # Imperial and other non-metric units
        ("inch", (m_per_inch, dimensions.length, 0.0, r"\rm{in}", False)),
        ("ft", (m_per_ft, dimensions.length, 0.0, r"\rm{ft}", False)),
        ("yd", (0.9144, dimensions.length, 0.0, r"\rm{yd}", False)),
        ("mile", (1609.344, dimensions.length, 0.0, r"\rm{mile}", False)),
        ("furlong", (m_per_ft * 660.0, dimensions.length, 0.0, r"\rm{fur}", False)),
        (
            "degF",
            (
                kelvin_per_rankine,
                dimensions.temperature,
                -459.67,
                r"^\circ\rm{F}",
                False,
            ),
        ),
        (
            "R",
            (kelvin_per_rankine, dimensions.temperature, 0.0, r"^\circ\rm{R}", False),
        ),
        (
            "lbf",
            (
                kg_per_pound * standard_gravity_m_per_s2,
                dimensions.force,
                0.0,
                r"\rm{lbf}",
                False,
            ),
        ),
        ("lb", (kg_per_pound, dimensions.mass, 0.0, r"\rm{lb}", False)),
        ("atm", (pascal_per_atm, dimensions.pressure, 0.0, r"\rm{atm}", False)),
        ("hp", (watt_per_horsepower, dimensions.power, 0.0, r"\rm{hp}", False)),
        ("oz", (kg_per_pound / 16.0, dimensions.mass, 0.0, r"\rm{oz}", False)),
        ("ton", (kg_per_pound * 2000.0, dimensions.mass, 0.0, r"\rm{ton}", False)),
        (
            "slug",
            (
                kg_per_pound * standard_gravity_m_per_s2 / m_per_ft,
                dimensions.mass,
                0.0,
                r"\rm{slug}",
                False,
            ),
        ),
        ("cal", (4.184, dimensions.energy, 0.0, r"\rm{cal}", True)),
        ("BTU", (1055.0559, dimensions.energy, 0.0, r"\rm{BTU}", False)),
        (
            "psi",
            (
                kg_per_pound * standard_gravity_m_per_s2 / m_per_inch ** 2,
                dimensions.pressure,
                0.0,
                r"\rm{psi}",
                False,
            ),
        ),
        ("smoot", (1.7018, dimensions.length, 0.0, r"\rm{smoot}", False)),
        # dimensionless stuff
        ("dimensionless", (1.0, dimensions.dimensionless, 0.0, r"", False)),
        ("%", (0.01, dimensions.dimensionless, 0.0, r"\%", False)),
        # times
        ("min", (sec_per_min, dimensions.time, 0.0, r"\rm{min}", False)),
        ("hr", (sec_per_hr, dimensions.time, 0.0, r"\rm{hr}", False)),
        ("day", (sec_per_day, dimensions.time, 0.0, r"\rm{d}", False)),
        ("yr", (sec_per_year, dimensions.time, 0.0, r"\rm{yr}", True)),
        # Velocities
        ("c", (speed_of_light_m_per_s, dimensions.velocity, 0.0, r"\rm{c}", False)),
        # Solar units
        ("Msun", (mass_sun_kg, dimensions.mass, 0.0, r"\rm{M}_\odot", False)),
        ("Rsun", (m_per_rsun, dimensions.length, 0.0, r"\rm{R}_\odot", False)),
        ("Lsun", (luminosity_sun_watts, dimensions.power, 0.0, r"\rm{L}_\odot", False)),
        (
            "Tsun",
            (temp_sun_kelvin, dimensions.temperature, 0.0, r"\rm{T}_\odot", False),
        ),
        (
            "Zsun",
            (metallicity_sun, dimensions.dimensionless, 0.0, r"\rm{Z}_\odot", False),
        ),
        ("Mjup", (mass_jupiter_kg, dimensions.mass, 0.0, r"\rm{M}_{\rm{Jup}}", False)),
        ("Mearth", (mass_earth_kg, dimensions.mass, 0.0, r"\rm{M}_\oplus", False)),
        ("Rjup", (m_per_rjup, dimensions.length, 0.0, r"\rm{R}_\mathrm{Jup}", False)),
        ("Rearth", (m_per_rearth, dimensions.length, 0.0, r"\rm{R}_\oplus", False)),
        # astro distances
        ("AU", (m_per_au, dimensions.length, 0.0, r"\rm{AU}", False)),
        ("ly", (m_per_ly, dimensions.length, 0.0, r"\rm{ly}", False)),
        ("pc", (m_per_pc, dimensions.length, 0.0, r"\rm{pc}", True)),
        # angles
        ("degree", (np.pi / 180.0, dimensions.angle, 0.0, r"^\circ", False)),
        ("arcmin", (np.pi / 10800.0, dimensions.angle, 0.0, r"\rm{arcmin}", False)),
        ("arcsec", (np.pi / 648000.0, dimensions.angle, 0.0, r"\rm{arcsec}", False)),
        ("mas", (np.pi / 648000000.0, dimensions.angle, 0.0, r"\rm{mas}", False)),
        ("hourangle", (np.pi / 12.0, dimensions.angle, 0.0, r"\rm{HA}", False)),
        ("sr", (1.0, dimensions.solid_angle, 0.0, r"\rm{sr}", False)),
        ("lat", (-np.pi / 180.0, dimensions.angle, 90.0, r"\rm{Latitude}", False)),
        ("lon", (np.pi / 180.0, dimensions.angle, -180.0, r"\rm{Longitude}", False)),
        # misc
        ("eV", (J_per_eV, dimensions.energy, 0.0, r"\rm{eV}", True)),
        ("amu", (amu_kg, dimensions.mass, 0.0, r"\rm{amu}", False)),
        ("Å", (m_per_ang, dimensions.length, 0.0, r"\AA", False)),
        ("Jy", (jansky_mks, dimensions.specific_flux, 0.0, r"\rm{Jy}", True)),
        ("counts", (1.0, dimensions.dimensionless, 0.0, r"\rm{counts}", False)),
        ("photons", (1.0, dimensions.dimensionless, 0.0, r"\rm{photons}", False)),
        ("me", (mass_electron_kg, dimensions.mass, 0.0, r"m_e", False)),
        ("mp", (mass_hydrogen_kg, dimensions.mass, 0.0, r"m_p", False)),
        ("Sv", (1.0, dimensions.specific_energy, 0.0, r"\rm{Sv}", True)),
        (
            "rayleigh",
            (2.5e9 / np.pi, dimensions.count_intensity, 0.0, r"\rm{R}", False),
        ),
        ("lambert", (1.0e4 / np.pi, dimensions.luminance, 0.0, r"\rm{L}", False)),
        ("nt", (1.0, dimensions.luminance, 0.0, r"\rm{nt}", False)),
        # Planck units
        ("m_pl", (planck_mass_kg, dimensions.mass, 0.0, r"m_{\rm{P}}", False)),
        ("l_pl", (planck_length_m, dimensions.length, 0.0, r"\ell_\rm{P}", False)),
        ("t_pl", (planck_time_s, dimensions.time, 0.0, r"t_{\rm{P}}", False)),
        (
            "T_pl",
            (planck_temperature_K, dimensions.temperature, 0.0, r"T_{\rm{P}}", False),
        ),
        ("q_pl", (planck_charge_C, dimensions.charge_mks, 0.0, r"q_{\rm{P}}", False)),
        ("E_pl", (planck_energy_J, dimensions.energy, 0.0, r"E_{\rm{P}}", False)),
        # Geometrized units
        ("m_geom", (mass_sun_kg, dimensions.mass, 0.0, r"\rm{M}_\odot", False)),
        (
            "l_geom",
            (
                newton_mks * mass_sun_kg / speed_of_light_m_per_s ** 2,
                dimensions.length,
                0.0,
                r"\rm{M}_\odot",
                False,
            ),
        ),
        (
            "t_geom",
            (
                newton_mks * mass_sun_kg / speed_of_light_m_per_s ** 3,
                dimensions.time,
                0.0,
                r"\rm{M}_\odot",
                False,
            ),
        ),
        # logarithmic units
        ("B", (neper_per_bel, dimensions.logarithmic, 0.0, r"\rm{B}", True)),
        ("Np", (1.0, dimensions.logarithmic, 0.0, r"\rm{Np}", True)),
    ]
)

# This dictionary formatting from magnitude package, credit to Juan Reyero.
unit_prefixes = OrderedDict(
    [
        ("Y", (1e24, "yotta")),
        ("Z", (1e21, "zetta")),
        ("E", (1e18, "exa")),
        ("P", (1e15, "peta")),
        ("T", (1e12, "tera")),
        ("G", (1e9, "giga")),
        ("M", (1e6, "mega")),
        ("k", (1e3, "kilo")),
        ("h", (1e2, "hecto")),
        ("da", (1e1, "deca")),
        ("d", (1e-1, "deci")),
        ("c", (1e-2, "centi")),
        ("m", (1e-3, "mili")),
        ("µ", (1e-6, "micro")),  # ('MICRO SIGN' U+00B5)
        ("u", (1e-6, "micro")),
        ("μ", (1e-6, "micro")),  # ('GREEK SMALL LETTER MU' U+03BC)
        ("n", (1e-9, "nano")),
        ("p", (1e-12, "pico")),
        ("f", (1e-15, "femto")),
        ("a", (1e-18, "atto")),
        ("z", (1e-21, "zepto")),
        ("y", (1e-24, "yocto")),
    ]
)

default_base_units = {
    dimensions.mass: "kg",
    dimensions.length: "m",
    dimensions.time: "s",
    dimensions.temperature: "K",
    dimensions.angle: "radian",
    dimensions.current_mks: "A",
    dimensions.luminous_intensity: "cd",
}

physical_constants = OrderedDict(
    [
        ("me", (mass_electron_kg, "kg", ["mass_electron", "electron_mass"])),
        ("amu", (amu_kg, "kg", ["atomic_mass_unit"])),
        ("Na", (avogadros_number, "mol**-1", ["Avogadros_number", "avogadros_number"])),
        ("mp", (mass_proton_kg, "kg", ["proton_mass", "mass_proton"])),
        ("mh", (mass_hydrogen_kg, "kg", ["hydrogen_mass", "mass_hydrogen"])),
        ("c", (speed_of_light_m_per_s, "m/s", ["clight", "speed_of_light"])),
        (
            "σ_T",
            (
                6.65245854533e-29,
                "m**2",
                ["sigma_thompson", "thompson_cross_section", "cross_section_thompson"],
            ),
        ),
        (
            "qp",
            (
                1.6021766208e-19,
                "C",
                ["proton_charge", "elementary_charge", "charge_proton"],
            ),
        ),
        ("qe", (-1.6021766208e-19, "C", ["electron_charge", "charge_electron"])),
        ("kb", (boltzmann_constant_J_per_K, "J/K", ["kboltz", "boltzmann_constant"])),
        (
            "G",
            (
                newton_mks,
                "m**3/kg/s**2",
                ["newtons_constant", "gravitational_constant"],
            ),
        ),
        ("h", (planck_mks, "J*s", ["planck_constant"])),
        ("hbar", (0.5 * planck_mks / np.pi, "J*s", ["reduced_planck_constant"])),
        ("σ", (5.670373e-8, "W/m**2/K**4", ["stefan_boltzmann_constant"])),
        ("Tcmb", (2.726, "K", ["CMB_temperature"])),
        (
            "Msun",
            (
                mass_sun_kg,
                "kg",
                ["msun", "m_sun", "m_Sun", "M_sun", "M_Sun", "solar_mass", "mass_sun"],
            ),
        ),
        ("Mjup", (mass_jupiter_kg, "kg", ["mjup", "jupiter_mass", "mass_jupiter"])),
        ("mercury_mass", (mass_mercury_kg, "kg", ["mass_mercury"])),
        ("venus_mass", (mass_venus_kg, "kg", ["mass_venus"])),
        ("Mearth", (mass_earth_kg, "kg", ["mearth", "earth_mass", "mass_earth"])),
        ("mars_mass", (mass_mars_kg, "kg", ["mass_mars"])),
        ("saturn_mass", (mass_saturn_kg, "kg", ["mass_saturn"])),
        ("uranus_mass", (mass_uranus_kg, "kg", ["mass_uranus"])),
        ("neptune_mass", (mass_neptune_kg, "kg", ["mass_neptune"])),
        ("m_pl", (planck_mass_kg, "kg", ["planck_mass"])),
        ("l_pl", (planck_length_m, "m", ["planck_length"])),
        ("t_pl", (planck_time_s, "s", ["planck_time"])),
        ("E_pl", (planck_energy_J, "J", ["planck_energy"])),
        ("q_pl", (planck_charge_C, "C", ["planck_charge"])),
        ("T_pl", (planck_temperature_K, "K", ["planck_temperature"])),
        ("mu_0", (mu_0, "N/A**2", ["vacuum_permeability", "magnetic_constant", "μ_0"])),
        (
            "eps_0",
            (
                eps_0,
                "C**2/N/m**2",
                ["vacuum_permittivity", "electric_constant", "ε_0", "epsilon_0"],
            ),
        ),
        ("standard_gravity", (standard_gravity_m_per_s2, "m/s**2", [])),
    ]
)

default_unit_name_alternatives = OrderedDict(
    [
        # base
        ("m", ("meter", "metre")),
        ("g", ("gram", "gramme")),
        ("s", ("second",)),
        ("K", ("degree_kelvin", "kelvin")),
        ("rad", ("radian",)),
        ("A", ("ampere", "amp", "Amp")),
        ("cd", ("candela",)),
        ("mol", ("mole",)),
        # some cgs
        ("dyn", ("dyne",)),
        ("erg", ("ergs",)),
        ("Ba", ("barye",)),
        ("G", ("gauss",)),
        ("statC", ("statcoulomb", "esu", "ESU", "electrostatic_unit")),
        ("statA", ("statampere",)),
        ("statV", ("statvolt",)),
        ("Mx", ("maxwell",)),
        # some SI
        ("J", ("joule",)),
        ("W", ("watt",)),
        ("Hz", ("hertz",)),
        ("N", ("newton",)),
        ("C", ("coulomb",)),
        ("T", ("tesla",)),
        ("Pa", ("pascal",)),
        ("V", ("volt",)),
        ("F", ("farad",)),
        ("H", ("henry",)),
        ("Ω", ("ohm", "Ohm")),
        ("Wb", ("weber",)),
        ("lm", ("lumen",)),
        ("lx", ("lux",)),
        ("degC", ("degree_celsius", "degree_Celsius", "celcius", "celsius", "°C")),
        # Imperial and other non-metric units
        ("inch", ("in",)),
        ("ft", ("foot",)),
        ("yd", ("yard",)),
        ("furlong", ("fur",)),
        ("degF", ("degree_fahrenheit", "degree_Fahrenheit", "fahrenheit", "°F")),
        ("R", ("degree_rankine", "rankine")),
        ("lbf", ("pound_force",)),
        ("lb", ("pound", "pound_mass", "lbm")),
        ("atm", ("atmosphere",)),
        ("hp", ("horsepower",)),
        ("oz", ("ounce",)),
        ("cal", ("calorie",)),
        ("BTU", ("british_thermal_unit",)),
        ("psi", ("pounds_per_square_inch",)),
        # dimensionless stuff
        ("dimensionless", ("_", "")),
        ("B", ("bel",)),
        ("Np", ("neper",)),
        # times
        ("min", ("minute",)),
        ("hr", ("hour",)),
        ("day", ("d",)),
        ("yr", ("year",)),
        # Solar units
        (
            "Msun",
            ("msun", "m_sun", "M_sun", "m_Sun", "solar_mass", "solMass", "mass_sun"),
        ),
        ("Rsun", ("rsun", "r_sun", "R_sun", "r_Sun", "solar_radius", "solRadius")),
        (
            "Lsun",
            ("lsun", "l_sun", "L_sun", "l_Sun", "solar_luminosity", "solLuminosity"),
        ),
        (
            "Tsun",
            ("t_sun", "tsun", "T_sun", "t_Sun", "solar_temperature", "solTemperature"),
        ),
        (
            "Zsun",
            ("z_sun", "zsun", "Z_sun", "z_Sun", "solar_metallicity", "solMetallicity"),
        ),
        ("Mjup", ("m_jup", "jupiter_mass")),
        ("Mearth", ("m_earth", "earth_mass")),
        ("Rjup", ("r_jup", "jupiter_radius")),
        ("Rearth", ("r_earth", "earth_radius")),
        # astro distances
        ("AU", ("au", "astronomical_unit")),
        ("pc", ("parsec",)),
        ("ly", ("light_year",)),
        # angles
        ("degree", ("deg",)),
        ("arcmin", ("arcminute",)),
        ("arcsec", ("arcsecond",)),
        ("mas", ("milliarcsecond",)),
        ("hourangle", ("HA",)),
        ("sr", ("steradian",)),
        ("lat", ("latitude", "degree_latitude")),
        ("lon", ("longitude", "degree_longitude")),
        # misc
        ("eV", ("electronvolt",)),
        ("amu", ("atomic_mass_unit",)),
        ("Å", ("angstrom",)),
        ("Jy", ("jansky",)),
        ("counts", ("count",)),
        ("photons", ("photon",)),
        ("me", ("electron_mass",)),
        ("mp", ("proton_mass",)),
        ("Sv", ("sievert",)),
        ("nt", ("nit",)),
        ("%", ("percent",)),
        # Planck units
        ("m_pl", ("planck_mass",)),
        ("l_pl", ("planck_length",)),
        ("t_pl", ("planck_time",)),
        ("T_pl", ("planck_temperature",)),
        ("q_pl", ("planck_charge",)),
        ("E_pl", ("planck_energy",)),
    ]
)


def generate_name_alternatives():
    names = defaultdict(list)
    inv_names = {}
    seen = set()

    def append_name(n, okey, key):
        if key not in seen:
            n.append(key)
            inv_names[key] = okey
            seen.add(key)
        else:
            if okey[0] not in ["u", "μ"]:
                raise RuntimeError(  # pragma: no cover
                    "Duplicate unit name found: {}, {}".format(key, okey)
                )

    for key, entry in default_unit_symbol_lut.items():
        append_name(names[key], key, key)
        # Are we SI prefixable or not?
        if entry[4]:
            for prefix in unit_prefixes:
                # This is specifically to work around
                # https://github.com/yt-project/unyt/issues/145
                if prefix in ["u", "μ", "µ"]:
                    used_prefix = "μ"
                else:
                    used_prefix = prefix
                append_name(names[prefix + key], used_prefix + key, prefix + key)
        elif len(key) > 3 and key.title() != key:
            if all([len(k) > 3 for k in key.split("_")]):
                append_name(names[key], key, key.title())
        if key in default_unit_name_alternatives:
            alternatives = default_unit_name_alternatives[key]
            # Are we SI prefixable or not?
            if entry[4]:
                for a in alternatives:
                    for up, up_data in unit_prefixes.items():
                        if len(a) < 4:
                            append_name(names[up + key], up + key, up + a)
                        alt = up_data[1] + a
                        if alt not in seen:
                            append_name(names[up + key], up + key, alt)
                        if alt.title() not in names[up + key]:
                            append_name(names[up + key], up + key, alt.title())
            for alt in alternatives:
                append_name(names[key], key, alt)
                if not alt.islower() or len(alt) < 4:
                    continue
                if alt.title() not in names[key]:
                    append_name(names[key], key, alt.title())
    return names, inv_names


name_alternatives, inv_name_alternatives = generate_name_alternatives()
