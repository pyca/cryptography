# -*- encoding: utf-8 -*-
"""

    Definitions used for tokenization of Icelandic text

    Copyright (C) 2020 Miðeind ehf.
    Original author: Vilhjálmur Þorsteinsson

    This software is licensed under the MIT License:

        Permission is hereby granted, free of charge, to any person
        obtaining a copy of this software and associated documentation
        files (the "Software"), to deal in the Software without restriction,
        including without limitation the rights to use, copy, modify, merge,
        publish, distribute, sublicense, and/or sell copies of the Software,
        and to permit persons to whom the Software is furnished to do so,
        subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
        IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
        CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
        TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
        SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""

from __future__ import absolute_import
from __future__ import unicode_literals

from typing import Dict, Tuple, Union, Callable

import sys
import re


# Mask away difference between Python 2 and 3
if sys.version_info >= (3, 0):
    items = lambda d: d.items()
    keys = lambda d: d.keys()
    make_str = lambda s: s
    unicode_chr = lambda c: chr(c)
    is_str = lambda s: isinstance(s, str)
    if sys.version_info >= (3, 5):
        # On Python >= 3.5, the typing module is available
        from typing import Callable
else:
    items = lambda d: d.iteritems()
    keys = lambda d: d.iterkeys()

    # pylint: disable=undefined-variable
    def make_str(s):
        if isinstance(s, unicode):
            return s
        # Assume that incoming byte strings are UTF-8 encoded
        return s.decode("utf-8")

    unicode_chr = lambda c: unichr(c)
    is_str = lambda s: isinstance(s, (unicode, str))


ACCENT = unicode_chr(769)
UMLAUT = unicode_chr(776)
SOFT_HYPHEN = unicode_chr(173)
ZEROWIDTH_SPACE = unicode_chr(8203)
ZEROWIDTH_NBSP = unicode_chr(65279)

# Preprocessing of unicode characters before tokenization
UNICODE_REPLACEMENTS = {
    # Translations of separate umlauts and accents to single glyphs.
    # The strings to the left in each tuple are two Unicode code
    # points: vowel + COMBINING ACUTE ACCENT (chr(769)) or
    # vowel + COMBINING DIAERESIS (chr(776)).
    "a" + ACCENT: "á",
    "a" + UMLAUT: "ä",
    "e" + ACCENT: "é",
    "e" + UMLAUT: "ë",
    "i" + ACCENT: "í",
    "o" + ACCENT: "ó",
    "u" + ACCENT: "ú",
    "u" + UMLAUT: "ü",
    "y" + ACCENT: "ý",
    "o" + UMLAUT: "ö",
    "A" + UMLAUT: "Ä",
    "A" + ACCENT: "Á",
    "E" + ACCENT: "É",
    "E" + UMLAUT: "Ë",
    "I" + ACCENT: "Í",
    "O" + ACCENT: "Ó",
    "U" + ACCENT: "Ú",
    "U" + UMLAUT: "Ü",
    "Y" + ACCENT: "Ý",
    "O" + UMLAUT: "Ö",
    # Also remove these unwanted characters
    SOFT_HYPHEN: "",
    ZEROWIDTH_SPACE: "",
    ZEROWIDTH_NBSP: "",
}
UNICODE_REGEX = re.compile(
    r"|".join(map(re.escape, keys(UNICODE_REPLACEMENTS))), re.UNICODE
)

# Hyphens are normalized to '-'
HYPHEN = "-"  # Normal hyphen
EN_DASH = "\u2013"  # "–"
EM_DASH = "\u2014"  # "—"

HYPHENS = HYPHEN + EN_DASH + EM_DASH

# Hyphens that may indicate composite words ('fjármála- og efnahagsráðuneyti')
COMPOSITE_HYPHENS = HYPHEN + EN_DASH
COMPOSITE_HYPHEN = EN_DASH

# Recognized punctuation
LEFT_PUNCTUATION = "([„‚«#$€£¥₽<"
RIGHT_PUNCTUATION = ".,:;)]!%‰?“»”’‛‘…>°"
CENTER_PUNCTUATION = '"*•&+=@©|'
NONE_PUNCTUATION = "^/±'´~\\" + HYPHEN + EN_DASH + EM_DASH
PUNCTUATION = (
    LEFT_PUNCTUATION + CENTER_PUNCTUATION + RIGHT_PUNCTUATION + NONE_PUNCTUATION
)
PUNCTUATION_REGEX = "[{0}]".format("|".join(re.escape(p) for p in PUNCTUATION))

# Punctuation types: left, center or right of word

TP_LEFT = 1  # Whitespace to the left
TP_CENTER = 2  # Whitespace to the left and right
TP_RIGHT = 3  # Whitespace to the right
TP_NONE = 4  # No whitespace
TP_WORD = 5  # Flexible whitespace depending on surroundings

# Matrix indicating correct spacing between tokens

TP_SPACE = (
    # Next token is:
    # LEFT  CENTER RIGHT   NONE   WORD
    # Last token was TP_LEFT:
    (False, True, False, False, False),
    # Last token was TP_CENTER:
    (True, True, True, True, True),
    # Last token was TP_RIGHT:
    (True, True, False, False, True),
    # Last token was TP_NONE:
    (False, True, False, False, False),
    # Last token was TP_WORD:
    (True, True, False, False, True),
)

# Punctuation that ends a sentence
END_OF_SENTENCE = frozenset([".", "?", "!", "…"])  # Removed […]
# Punctuation symbols that may additionally occur at the end of a sentence
SENTENCE_FINISHERS = frozenset([")", "]", "“", "»", "”", "’", '"', "[…]"])
# Punctuation symbols that may occur inside words
# Note that an EM_DASH is not allowed inside a word and will split words if present
PUNCT_INSIDE_WORD = frozenset([".", "'", "‘", "´", "’", HYPHEN, EN_DASH])
# Punctuation symbols that can end words
PUNCT_ENDING_WORD = frozenset(["'", "²", "³"])
# Punctuation symbols that may occur together
PUNCT_COMBINATIONS = frozenset(["?", "!", "…"])

# Single and double quotes
SQUOTES = "'‚‛‘´"
DQUOTES = '"“„”«»'

CLOCK_ABBREVS = frozenset(("kl", "kl.", "klukkan"))

# Allowed first digits in Icelandic telephone numbers
TELNO_PREFIXES = "45678"

# Known telephone country codes
COUNTRY_CODES = frozenset((
    "354", "+354", "00354",
))

# Words that can precede a year number; will be assimilated into the year token
YEAR_WORD = frozenset(("árið", "ársins", "árinu"))

# Characters that can start a numeric token
DIGITS_PREFIX = frozenset([d for d in "0123456789"])
SIGN_PREFIX = frozenset(("+", "-"))

# Month names and numbers
MONTHS = {
    "janúar": 1,
    "janúars": 1,
    "febrúar": 2,
    "febrúars": 2,
    "mars": 3,
    "apríl": 4,
    "apríls": 4,
    "maí": 5,
    "maís": 5,
    "júní": 6,
    "júnís": 6,
    "júlí": 7,
    "júlís": 7,
    "ágúst": 8,
    "ágústs": 8,
    "september": 9,
    "septembers": 9,
    "október": 10,
    "októbers": 10,
    "nóvember": 11,
    "nóvembers": 11,
    "desember": 12,
    "desembers": 12,
    "jan.": 1,
    "feb.": 2,
    "mar.": 3,
    "apr.": 4,
    "jún.": 6,
    "júl.": 7,
    "ág.": 8,
    "ágú.": 8,
    "sep.": 9,
    "sept.": 9,
    "okt.": 10,
    "nóv.": 11,
    "des.": 12,
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "jún": 6,
    "júl": 7,
    "ág": 8,
    "ágú": 8,
    "sep": 9,
    "sept": 9,
    "okt": 10,
    "nóv": 11,
    "des": 12,
}

# The masculine Icelandic name should not be identified as a month
MONTH_BLACKLIST = frozenset(("Ágúst",))

# Word forms that are not unambiguous as month names
AMBIGUOUS_MONTH_NAMES = frozenset(
    ("jan", "Jan", "mar", "Mar", "júl", "Júl", "des", "Des", "Ágúst")
)

# Max number of days in each month, indexed so that 1=January
DAYS_IN_MONTH = (0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)

# Days of the month spelled out
# DAYS_OF_MONTH = {
#     "fyrsti": 1,
#     "fyrsta": 1,
#     "annar": 2,
#     "annan": 2,
#     "þriðji": 3,
#     "þriðja": 3,
#     "fjórði": 4,
#     "fjórða": 4,
#     "fimmti": 5,
#     "fimmta": 5,
#     "sjötti": 6,
#     "sjötta": 6,
#     "sjöundi": 7,
#     "sjöunda": 7,
#     "áttundi": 8,
#     "áttunda": 8,
#     "níundi": 9,
#     "níunda": 9,
#     "tíundi": 10,
#     "tíunda": 10,
#     "ellefti": 11,
#     "ellefta": 11,
#     "tólfti": 12,
#     "tólfta": 12,
#     "þrettándi": 13,
#     "þrettánda": 13,
#     "fjórtándi": 14,
#     "fjórtánda": 14,
#     "fimmtándi": 15,
#     "fimmtánda": 15,
#     "sextándi": 16,
#     "sextánda": 16,
#     "sautjándi": 17,
#     "sautjánda": 17,
#     "átjándi": 18,
#     "átjánda": 18,
#     "nítjándi": 19,
#     "nítjánda": 19,
#     "tuttugasti": 20,
#     "tuttugasta": 20,
#     "þrítugasti": 30,
#     "þrítugasta": 30,
# }

# Time of day expressions spelled out
CLOCK_NUMBERS = {
    "eitt": [1, 0, 0],
    "tvö": [2, 0, 0],
    "þrjú": [3, 0, 0],
    "fjögur": [4, 0, 0],
    "fimm": [5, 0, 0],
    "sex": [6, 0, 0],
    "sjö": [7, 0, 0],
    "átta": [8, 0, 0],
    "níu": [9, 0, 0],
    "tíu": [10, 0, 0],
    "ellefu": [11, 0, 0],
    "tólf": [12, 0, 0],
    "hálfeitt": [12, 30, 0],
    "hálftvö": [1, 30, 0],
    "hálfþrjú": [2, 30, 0],
    "hálffjögur": [3, 30, 0],
    "hálffimm": [4, 30, 0],
    "hálfsex": [5, 30, 0],
    "hálfsjö": [6, 30, 0],
    "hálfátta": [7, 30, 0],
    "hálfníu": [8, 30, 0],
    "hálftíu": [9, 30, 0],
    "hálfellefu": [10, 30, 0],
    "hálftólf": [11, 30, 0],
}

# Set of words only possible in temporal phrases
CLOCK_HALF = frozenset(
    [
        "hálfeitt",
        "hálftvö",
        "hálfþrjú",
        "hálffjögur",
        "hálffimm",
        "hálfsex",
        "hálfsjö",
        "hálfátta",
        "hálfníu",
        "hálftíu",
        "hálfellefu",
        "hálftólf",
    ]
)

# 'Current Era', 'Before Current Era'
CE = frozenset(("e.Kr", "e.Kr."))  # !!! Add AD and CE here?
BCE = frozenset(("f.Kr", "f.Kr."))  # !!! Add BCE here?
CE_BCE = CE | BCE

# Supported ISO 4217 currency codes
CURRENCY_ABBREV = frozenset(
    (
        "ISK",  # Icelandic króna
        "DKK",  # Danish krone
        "NOK",  # Norwegian krone
        "SEK",  # Swedish krona
        "GBP",  # British pounds sterling
        "USD",  # US dollar
        "EUR",  # Euro
        "CAD",  # Canadian dollar
        "AUD",  # Australian dollar
        "CHF",  # Swiss franc
        "JPY",  # Japanese yen
        "PLN",  # Polish złoty
        "RUB",  # Russian ruble
        "CZK",  # Czech koruna
        "INR",  # Indian rupee
        "IDR",  # Indonesian rupiah
        "CNY",  # Chinese renminbi
        "RMB",  # Chinese renminbi (alternate)
        "HKD",  # Hong Kong dollar
        "NZD",  # New Zealand dollar
        "SGD",  # Singapore dollar
        "MXN",  # Mexican peso
        "ZAR",  # South African rand
    )
)

# Map symbols to currency abbreviations
CURRENCY_SYMBOLS = {
    "$": "USD",
    "€": "EUR",
    "£": "GBP",
    "¥": "JPY",  # Also used for China's renminbi (yuan)
    "₽": "RUB",  # Russian ruble
}

# Single-character vulgar fractions in Unicode
SINGLECHAR_FRACTIONS = "↉⅒⅑⅛⅐⅙⅕¼⅓½⅖⅔⅜⅗¾⅘⅝⅚⅞"

# Derived unit : (base SI unit, conversion factor/function)
SI_UNITS = {
    # Distance
    "m": ("m", 1.0),
    "mm": ("m", 1.0e-3),
    "μm": ("m", 1.0e-6),
    "cm": ("m", 1.0e-2),
    "sm": ("m", 1.0e-2),
    "km": ("m", 1.0e3),
    "ft": ("m", 0.3048),  # feet
    "mi": ("m", 1609.34),  # miles
    # Area
    "m²": ("m²", 1.0),
    "fm": ("m²", 1.0),
    "km²": ("m²", 1.0e6),
    "cm²": ("m²", 1.0e-2),
    "ha": ("m²", 1.0e4),
    # Volume
    "m³": ("m³", 1.0),
    "cm³": ("m³", 1.0e-6),
    "km³": ("m³", 1.0e9),
    "l": ("m³", 1.0e-3),
    "ltr": ("m³", 1.0e-3),
    "dl": ("m³", 1.0e-4),
    "cl": ("m³", 1.0e-5),
    "ml": ("m³", 1.0e-6),
    "gal": ("m³", 3.78541e-3),
    "bbl": ("m³", 158.987294928e-3),
    # Temperature
    "K": ("K", 1.0),
    "°K": ("K", 1.0),  # Strictly speaking this should be K, not °K
    "°C": ("K", lambda x: x + 273.15),
    "°F": ("K", lambda x: (x + 459.67) * 5 / 9),
    # Mass
    "g": ("kg", 1.0e-3),
    "gr": ("kg", 1.0e-3),
    "kg": ("kg", 1.0),
    "t": ("kg", 1.0e3),
    "mg": ("kg", 1.0e-6),
    "μg": ("kg", 1.0e-9),
    "tn": ("kg", 1.0e3),
    "lb": ("kg", 0.453592),
    # Duration
    "s": ("s", 1.0),
    "ms": ("s", 1.0e-3),
    "μs": ("s", 1.0e-6),
    "klst": ("s", 3600.0),
    "mín": ("s", 60.0),
    # Force
    "N": ("N", 1.0),
    "kN": ("N", 1.0e3),
    # Energy
    "Nm": ("J", 1.0),
    "J": ("J", 1.0),
    "kJ": ("J", 1.0e3),
    "MJ": ("J", 1.0e6),
    "GJ": ("J", 1.0e9),
    "TJ": ("J", 1.0e12),
    "kWh": ("J", 3.6e6),
    "MWh": ("J", 3.6e9),
    "kWst": ("J", 3.6e6),
    "MWst": ("J", 3.6e9),
    "kcal": ("J", 4184),
    "cal": ("J", 4.184),
    # Power
    "W": ("W", 1.0),
    "mW": ("W", 1.0e-3),
    "kW": ("W", 1.0e3),
    "MW": ("W", 1.0e6),
    "GW": ("W", 1.0e9),
    "TW": ("W", 1.0e12),
    # Electric potential
    "V": ("V", 1.0),
    "mV": ("V", 1.0e-3),
    "kV": ("V", 1.0e3),
    # Electric current
    "A": ("A", 1.0),
    "mA": ("A", 1.0e-3),
    # Frequency
    "Hz": ("Hz", 1.0),
    "kHz": ("Hz", 1.0e3),
    "MHz": ("Hz", 1.0e6),
    "GHz": ("Hz", 1.0e9),
    # Pressure
    "Pa": ("Pa", 1.0),
    "hPa": ("Pa", 1.0e2),
    # Angle
    "°": ("°", 1.0),  # Degree
    # Percentage and promille
    "%": ("%", 1.0),
    "‰": ("‰", 0.1),
}  # type: Dict[str, Tuple[str, Union[float, Callable[[float], float]]]]

DIRECTIONS = {
    "N": "Norður",
}

SI_UNITS_SET = frozenset(keys(SI_UNITS))
SI_UNITS_REGEX_STRING = r"|".join(
    map(
        # If the unit ends with a letter, don't allow the next character
        # after it to be a letter (i.e. don't match '220Volts' as '220V')
        lambda unit: unit + r"(?!\w)" if unit[-1].isalpha() else unit,
        # Sort in descending order by length, so that longer strings
        # are matched before shorter ones
        sorted(keys(SI_UNITS), key=lambda s: len(s), reverse=True)
    )
)
SI_UNITS_REGEX = re.compile(r"({0})".format(SI_UNITS_REGEX_STRING), re.UNICODE)

CURRENCY_REGEX_STRING = r"|".join(
    map(
        # Sort in descending order by length, so that longer strings
        # are matched before shorter ones
        re.escape,
        sorted(keys(CURRENCY_SYMBOLS), key=lambda s: len(s), reverse=True)
    )
)

# Combined pattern regex for SI units, percentage, promille and currency symbols
UNIT_REGEX_STRING = SI_UNITS_REGEX_STRING + r"|" + CURRENCY_REGEX_STRING

# Icelandic-style number, followed by a unit
NUM_WITH_UNIT_REGEX1 = re.compile(
    r"([-+]?\d+(\.\d\d\d)*(,\d+)?)({0})".format(UNIT_REGEX_STRING),
    re.UNICODE
)

# English-style number, followed by a unit
NUM_WITH_UNIT_REGEX2 = re.compile(
    r"([-+]?\d+(,\d\d\d)*(\.\d+)?)({0})".format(UNIT_REGEX_STRING),
    re.UNICODE
)

# One or more digits, followed by a unicode vulgar fraction char (e.g. '2½')
# and a unit (SI, percent or currency symbol)
NUM_WITH_UNIT_REGEX3 = re.compile(
    r"(\d+)([\u00BC-\u00BE\u2150-\u215E])({0})".format(UNIT_REGEX_STRING),
    re.UNICODE
)


# If the handle_kludgy_ordinals option is set to
# KLUDGY_ORDINALS_PASS_THROUGH, we do not convert
# kludgy ordinals but pass them through as word tokens.
KLUDGY_ORDINALS_PASS_THROUGH = 0
# If the handle_kludgy_ordinals option is set to
# KLUDGY_ORDINALS_MODIFY, we convert '1sti' to 'fyrsti', etc.,
# and return the modified word as a token.
KLUDGY_ORDINALS_MODIFY = 1
# If the handle_kludgy_ordinals option is set to
# KLUDGY_ORDINALS_TRANSLATE, we convert '1sti' to TOK.Ordinal('1sti', 1), etc.,
# but otherwise pass the original word through as a word token ('2ja').
KLUDGY_ORDINALS_TRANSLATE = 2

# Incorrectly written ('kludgy') ordinals
ORDINAL_ERRORS = {
    "1sti": "fyrsti",
    "1sta": "fyrsta",
    "1stu": "fyrstu",
    "3ji": "þriðji",
    # "3ja": "þriðja",  # þriggja
    "3ju": "þriðju",
    "4ði": "fjórði",
    "4ða": "fjórða",
    "4ðu": "fjórðu",
    "5ti": "fimmti",
    "5ta": "fimmta",
    "5tu": "fimmtu",
    "2svar": "tvisvar",
    "3svar": "þrisvar",
    "2ja": "tveggja",
    "3ja": "þriggja",
    "4ra": "fjögurra",
}

# Translations of kludgy ordinal words into numbers
ORDINAL_NUMBERS = {
    "1sti": 1,
    "1sta": 1,
    "1stu": 1,
    "3ji": 3,
    "3ja": 3,
    "3ju": 3,
    "4ði": 4,
    "4ða": 4,
    "4ðu": 4,
    "5ti": 5,
    "5ta": 5,
    "5tu": 5
}

# Handling of Roman numerals

RE_ROMAN_NUMERAL = re.compile(
    r"^M{0,4}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})$"
)

ROMAN_NUMERAL_MAP = tuple(
    zip(
        (1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1),
        ("M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"),
    )
)


def roman_to_int(s):
    """ Quick and dirty conversion of an already validated Roman numeral to integer """
    # Adapted from http://code.activestate.com/recipes/81611-roman-numerals/
    i = result = 0
    for integer, numeral in ROMAN_NUMERAL_MAP:
        while s[i : i + len(numeral)] == numeral:
            result += integer
            i += len(numeral)
    assert i == len(s)
    return result


# Recognize words that multiply numbers
MULTIPLIERS = {
    # "núll": 0,
    # "hálfur": 0.5,
    # "helmingur": 0.5,
    # "þriðjungur": 1.0 / 3,
    # "fjórðungur": 1.0 / 4,
    # "fimmtungur": 1.0 / 5,
    "einn": 1,
    "tveir": 2,
    "þrír": 3,
    "fjórir": 4,
    "fimm": 5,
    "sex": 6,
    "sjö": 7,
    "átta": 8,
    "níu": 9,
    "tíu": 10,
    "ellefu": 11,
    "tólf": 12,
    "þrettán": 13,
    "fjórtán": 14,
    "fimmtán": 15,
    "sextán": 16,
    "sautján": 17,
    "seytján": 17,
    "átján": 18,
    "nítján": 19,
    "tuttugu": 20,
    "þrjátíu": 30,
    "fjörutíu": 40,
    "fimmtíu": 50,
    "sextíu": 60,
    "sjötíu": 70,
    "áttatíu": 80,
    "níutíu": 90,
    # "par": 2,
    # "tugur": 10,
    # "tylft": 12,
    "hundrað": 100,
    "þúsund": 1000,  # !!! Bæði hk og kvk!
    "þús.": 1000,
    "milljón": 1e6,
    "milla": 1e6,
    "millj.": 1e6,
    "mljó.": 1e6,
    "milljarður": 1e9,
    "miljarður": 1e9,
    "ma.": 1e9,
    "mrð.": 1e9,
}

# Recognize words for percentages
PERCENTAGES = {
    "prósent": 1,
    "prósenta": 1,
    "prósenti": 1,
    "prósents": 1,
    "prósentur": 1,
    "prósentum": 1,
    "hundraðshluti": 1,
    "hundraðshluta": 1,
    "hundraðshlutar": 1,
    "hundraðshlutum": 1,
    "prósentustig": 1,
    "prósentustigi": 1,
    "prósentustigs": 1,
    "prósentustigum": 1,
    "prósentustiga": 1,
}

# Amount abbreviations including 'kr' for the ISK
# Corresponding abbreviations are found in Abbrev.conf
AMOUNT_ABBREV = {
    "kr.": 1,
    "kr": 1,
    "krónur": 1,
    "þ.kr.": 1e3,
    "þ.kr": 1e3,
    "þús.kr.": 1e3,
    "þús.kr": 1e3,
    "m.kr.": 1e6,
    "m.kr": 1e6,
    "mkr.": 1e6,
    "mkr": 1e6,
    "millj.kr.": 1e6,
    "millj.kr": 1e6,
    "mljó.kr.": 1e6,
    "mljó.kr": 1e6,
    "ma.kr.": 1e9,
    "ma.kr": 1e9,
    "mö.kr.": 1e9,
    "mö.kr": 1e9,
    "mlja.kr.": 1e9,
    "mlja.kr": 1e9,
}

# Króna amount strings allowed before a number, e.g. "kr. 9.900"
ISK_AMOUNT_PRECEDING = frozenset(("kr.", "kr", "krónur"))

# URL prefixes. Note that this list should not contain www since
# www.something.com is a domain token, not a URL token.
URL_PREFIXES = ("http://", "https://", "file://")

TOP_LEVEL_DOMAINS = frozenset(
    (
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        "arpa",
        "eu",
        "biz",
        "info",
        "xyz",
        "online",
        "site",
        "tech",
        "top",
        "space",
        "news",
        "pro",
        "club",
        "loan",
        "win",
        "vip",
        "icu",
        "app",
        "blog",
        "shop",
        "work",
        "ltd",
        "mobi",
        "live",
        "store",
        "gdn",
        "art",
        # ccTLDs
        "ac",
        "ad",
        "ae",
        "af",
        "ag",
        "ai",
        "al",
        "am",
        "ao",
        "aq",
        "ar",
        "as",
        "at",
        "au",
        "aw",
        "ax",
        "az",
        "ba",
        "bb",
        "bd",
        "be",
        "bf",
        "bg",
        "bh",
        "bi",
        "bj",
        "bm",
        "bn",
        "bo",
        "br",
        "bs",
        "bt",
        "bw",
        "by",
        "bz",
        "ca",
        "cc",
        "cd",
        "cf",
        "cg",
        "ch",
        "ci",
        "ck",
        "cl",
        "cm",
        "cn",
        "co",
        "cr",
        "cu",
        "cv",
        "cw",
        "cx",
        "cy",
        "cz",
        "de",
        "dj",
        "dk",
        "dm",
        "do",
        "dz",
        "ec",
        "ee",
        "eg",
        "er",
        "es",
        "et",
        "eu",
        "fi",
        "fj",
        "fk",
        "fm",
        "fo",
        "fr",
        "ga",
        "gd",
        "ge",
        "gf",
        "gg",
        "gh",
        "gi",
        "gl",
        "gm",
        "gn",
        "gp",
        "gq",
        "gr",
        "gs",
        "gt",
        "gu",
        "gw",
        "gy",
        "hk",
        "hm",
        "hn",
        "hr",
        "ht",
        "hu",
        "id",
        "ie",
        "il",
        "im",
        "in",
        "io",
        "iq",
        "ir",
        "is",
        "it",
        "je",
        "jm",
        "jo",
        "jp",
        "ke",
        "kg",
        "kh",
        "ki",
        "km",
        "kn",
        "kp",
        # "kr", # Gives us trouble with "kr" abbreviation (e.g. "þús.kr" is a legitimate domain name)
        "kw",
        "ky",
        "kz",
        "la",
        "lb",
        "lc",
        "li",
        "lk",
        "lr",
        "ls",
        "lt",
        "lu",
        "lv",
        "ly",
        "ma",
        "mc",
        "md",
        "me",
        "mg",
        "mh",
        "mk",
        "ml",
        "mm",
        "mn",
        "mo",
        "mp",
        "mq",
        "mr",
        "ms",
        "mt",
        "mu",
        "mv",
        "mw",
        "mx",
        "my",
        "mz",
        "na",
        "nc",
        "ne",
        "nf",
        "ng",
        "ni",
        "nl",
        "no",
        "np",
        "nr",
        "nu",
        "nz",
        "om",
        "pa",
        "pe",
        "pf",
        "pg",
        "ph",
        "pk",
        "pl",
        "pm",
        "pn",
        "pr",
        "ps",
        "pt",
        "pw",
        "py",
        "qa",
        "re",
        "ro",
        "rs",
        "ru",
        "rw",
        "sa",
        "sb",
        "sc",
        "sd",
        "se",
        "sg",
        "sh",
        "si",
        "sk",
        "sl",
        "sm",
        "sn",
        "so",
        "sr",
        "ss",
        "st",
        "sv",
        "sx",
        "sy",
        "sz",
        "tc",
        "td",
        "tf",
        "tg",
        "th",
        "tj",
        "tk",
        "tl",
        "tm",
        "tn",
        "to",
        "tr",
        "tt",
        "tv",
        "tw",
        "tz",
        "ua",
        "ug",
        "uk",
        "us",
        "uy",
        "uz",
        "va",
        "vc",
        "ve",
        "vg",
        "vi",
        "vn",
        "vu",
        "wf",
        "ws",
        "ye",
        "yt",
        "za",
        "zm",
        "zw",
    )
)

# This is a small hack to satisfy the Mypy type checker
_escape = lambda s: re.escape(s)  # type: Callable[[str], str]

# Regex to recognise domain names
MIN_DOMAIN_LENGTH = 4  # E.g. "t.co"
DOMAIN_REGEX = re.compile(
    r"({0})({1}*)$".format(
        r"|".join(r"\w\." + d for d in map(_escape, TOP_LEVEL_DOMAINS)),
        PUNCTUATION_REGEX,
    ),
    re.UNICODE,
)

# A list of the symbols of the natural elements.
# Note that single-letter symbols should follow two-letter symbols,
# so that regexes do not match the single-letter ones greedily before
# the two-letter ones.
ELEMENTS = (
    "Ac",
    "Ag",
    "Al",
    "Am",
    "Ar",
    "As",
    "At",
    "Au",
    "Ba",
    "Be",
    "Bh",
    "Bi",
    "Bk",
    "Br",
    "B",
    "Ca",
    "Cd",
    "Ce",
    "Cf",
    "Cl",
    "Cm",
    "Cn",
    "Co",
    "Cr",
    "Cs",
    "Cu",
    "C",
    "Db",
    "Ds",
    "Dy",
    "Er",
    "Es",
    "Eu",
    "Fe",
    "Fl",
    "Fm",
    "Fr",
    "F",
    "Ga",
    "Gd",
    "Ge",
    "He",
    "Hf",
    "Hg",
    "Ho",
    "Hs",
    "H",
    "In",
    "Ir",
    "I",
    "Kr",
    "K",
    "La",
    "Li",
    "Lr",
    "Lu",
    "Lv",
    "Mc",
    "Md",
    "Mg",
    "Mn",
    "Mo",
    "Mt",
    "Na",
    "Nb",
    "Nd",
    "Ne",
    "Nh",
    "Ni",
    "No",
    "Np",
    "N",
    "Og",
    "Os",
    "O",
    "Pa",
    "Pb",
    "Pd",
    "Pm",
    "Po",
    "Pr",
    "Pt",
    "Pu",
    "P",
    "Ra",
    "Rb",
    "Re",
    "Rf",
    "Rg",
    "Rh",
    "Rn",
    "Ru",
    "Sb",
    "Sc",
    "Se",
    "Sg",
    "Si",
    "Sm",
    "Sn",
    "Sr",
    "S",
    "Ta",
    "Tb",
    "Tc",
    "Te",
    "Th",
    "Ti",
    "Tl",
    "Tm",
    "Ts",
    "U",
    "V",
    "W",
    "Xe",
    "Yb",
    "Y",
    "Zn",
    "Zr",
)

# Regex to recognize molecules ('H2SO4')
# Note that we place a further constraint on the token so that
# it must contain at least one digit to qualify as a molecular formula
ELEMENTS_REGEX = r"|".join(ELEMENTS)
MOLECULE_REGEX = re.compile(r"^(({0})+\d*)+".format(ELEMENTS_REGEX))
MOLECULE_FILTER = re.compile(r"\d")


# Validation of Icelandic social security numbers
KT_MAGIC = [3, 2, 7, 6, 5, 4, 0, 3, 2]


def valid_ssn(kt):
    """ Validate Icelandic social security number """
    if not kt or len(kt) != 11 or kt[6] != "-":
        return False
    m = 11 - sum((ord(kt[i]) - 48) * KT_MAGIC[i] for i in range(9)) % 11
    c = ord(kt[9]) - 48
    return m == 11 if c == 0 else m == c
