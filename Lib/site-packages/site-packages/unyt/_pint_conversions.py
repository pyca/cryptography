"""
Stuff for pint conversions

"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------


pint_aliases = {
    "meter": "m",
    "second": "s",
    "gram": "g",
    "joule": "J",
    "franklin": "esu",
    "dyne": "dyn",
    "parsec": "pc",
    "mole": "mol",
    "rankine": "R",
    "watt": "W",
    "pascal": "Pa",
    "tesla": "T",
    "kelvin": "K",
    "year": "yr",
    "minute": "min",
    "hour": "hr",
    "volt": "V",
    "ampere": "A",
    "foot": "ft",
    "coulomb": "C",
    "newton": "N",
    "hertz": "Hz",
    "arcsecond": "arcsec",
    "arcminute": "arcmin",
    "speed_of_light": "c",
    "esu_per_second": "statA",
    "atomic_mass_unit": "amu",
    "astronomical_unit": "au",
    "light_year": "ly",
    "electron_mass": "me",
    "proton_mass": "mp",
}

pint_prefixes = {
    "yotta": "Y",
    "zetta": "Z",
    "exa": "E",
    "peta": "P",
    "tera": "T",
    "giga": "G",
    "mega": "M",
    "kilo": "k",
    "deci": "d",
    "centi": "c",
    "milli": "m",
    "micro": "u",
    "nano": "n",
    "pico": "p",
    "femto": "f",
    "atto": "a",
    "zepto": "z",
    "yocto": "y",
}


def convert_pint_units(unit_expr):
    uexpr = unit_expr
    pfx = ""
    for prefix in pint_prefixes:
        if unit_expr.startswith(prefix):
            pfx = pint_prefixes[prefix]
            uexpr = uexpr[len(prefix) :]
            break
    if uexpr in pint_aliases:
        uexpr = pint_aliases[uexpr]
        if pfx == "":
            return uexpr
        else:
            return pfx + uexpr
    # If we can't figure it out just pass it and see
    # what happens
    return unit_expr
