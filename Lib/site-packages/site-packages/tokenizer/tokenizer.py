# -*- encoding: utf-8 -*-
"""

    Tokenizer for Icelandic text

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


    The function tokenize() consumes a text string and
    returns a generator of tokens. Each token is a tuple,
    typically having the form (type, word, meaning),
    where type is one of the constants specified in the
    TOK class, word is the original word found in the
    source text, and meaning contains auxiliary information
    depending on the token type (such as the definition of
    an abbreviation, or the day, month and year for dates).

"""

from __future__ import absolute_import
from __future__ import unicode_literals

from collections import namedtuple

import re
import datetime
import unicodedata

from .abbrev import Abbreviations
# pylint: disable=unused-wildcard-import
from .definitions import *


# Named tuple for tokens
Tok = namedtuple("Tok", ["kind", "txt", "val"])


class TOK:

    """ Token types """

    # Punctuation
    PUNCTUATION = 1
    # Time hh:mm:ss
    TIME = 2
    # Date yyyy-mm-dd
    DATE = 3
    # Year, four digits
    YEAR = 4
    # Number, integer or real
    NUMBER = 5
    # Word, which may contain hyphens and apostrophes
    WORD = 6
    # Telephone number: 7 digits, eventually preceded by country code
    TELNO = 7
    # Percentage (number followed by percent or promille sign)
    PERCENT = 8
    # A Uniform Resource Locator (URL): https://example.com/path?p=100
    URL = 9
    # An ordinal number, eventually using Roman numerals (1., XVII.)
    ORDINAL = 10
    # A timestamp (not emitted by Tokenizer)
    TIMESTAMP = 11
    # A currency sign or code
    CURRENCY = 12
    # An amount, i.e. a quantity with a currency code
    AMOUNT = 13
    # Person name (not used by Tokenizer)
    PERSON = 14
    # E-mail address (somebody@somewhere.com)
    EMAIL = 15
    # Entity name (not used by Tokenizer)
    ENTITY = 16
    # Unknown token type
    UNKNOWN = 17
    # Absolute date
    DATEABS = 18
    # Relative date
    DATEREL = 19
    # Absolute time stamp, yyyy-mm-dd hh:mm:ss
    TIMESTAMPABS = 20
    # Relative time stamp, yyyy-mm-dd hh:mm:ss
    # where at least of yyyy, mm or dd is missing
    TIMESTAMPREL = 21
    # A measured quantity with its unit (220V, 0.5 km)
    MEASUREMENT = 22
    # Number followed by letter (a-z), often seen in addresses (Skógarstígur 4B)
    NUMWLETTER = 23
    # Internet domain name (an.example.com)
    DOMAIN = 24
    # Hash tag (#metoo)
    HASHTAG = 25
    # Chemical compound ('H2SO4')
    MOLECULE = 26
    # Social security number ('kennitala')
    SSN = 27
    # Social media user name ('@username_123')
    USERNAME = 28
    # Serial number ('394-8362')
    SERIALNUMBER = 29
    # Company name ('Google Inc.')
    COMPANY = 30
    # Sentence split token
    S_SPLIT = 10000
    # Paragraph begin
    P_BEGIN = 10001
    # Paragraph end
    P_END = 10002
    # Sentence begin
    S_BEGIN = 11001
    # Sentence end
    S_END = 11002
    # End sentinel
    X_END = 12001

    END = frozenset((P_END, S_END, X_END, S_SPLIT))
    TEXT = frozenset((WORD, PERSON, ENTITY, MOLECULE, COMPANY))
    TEXT_EXCL_PERSON = frozenset((WORD, ENTITY, MOLECULE, COMPANY))

    # Token descriptive names

    descr = {
        PUNCTUATION: "PUNCTUATION",
        TIME: "TIME",
        TIMESTAMP: "TIMESTAMP",
        TIMESTAMPABS: "TIMESTAMPABS",
        TIMESTAMPREL: "TIMESTAMPREL",
        DATE: "DATE",
        DATEABS: "DATEABS",
        DATEREL: "DATEREL",
        YEAR: "YEAR",
        NUMBER: "NUMBER",
        NUMWLETTER: "NUMBER WITH LETTER",
        CURRENCY: "CURRENCY",
        AMOUNT: "AMOUNT",
        MEASUREMENT: "MEASUREMENT",
        PERSON: "PERSON",
        WORD: "WORD",
        UNKNOWN: "UNKNOWN",
        TELNO: "TELNO",
        PERCENT: "PERCENT",
        URL: "URL",
        DOMAIN: "DOMAIN",
        HASHTAG: "HASHTAG",
        EMAIL: "EMAIL",
        ORDINAL: "ORDINAL",
        ENTITY: "ENTITY",
        MOLECULE: "MOLECULE",
        SSN: "SSN",
        USERNAME: "USERNAME",
        SERIALNUMBER: "SERIALNUMBER",
        COMPANY : "COMPANY",
        S_SPLIT: "SPLIT SENT",
        P_BEGIN: "BEGIN PARA",
        P_END: "END PARA",
        S_BEGIN: "BEGIN SENT",
        S_END: "END SENT",
    }

    # Token constructors

    @staticmethod
    def Punctuation(w, normalized=None):
        tp = TP_CENTER  # Default punctuation type
        if normalized is None:
            normalized = w
        if normalized and len(normalized) == 1:
            if normalized in LEFT_PUNCTUATION:
                tp = TP_LEFT
            elif normalized in RIGHT_PUNCTUATION:
                tp = TP_RIGHT
            elif normalized in NONE_PUNCTUATION:
                tp = TP_NONE
        return Tok(TOK.PUNCTUATION, w, (tp, normalized))

    @staticmethod
    def Time(w, h, m, s):
        return Tok(TOK.TIME, w, (h, m, s))

    @staticmethod
    def Date(w, y, m, d):
        return Tok(TOK.DATE, w, (y, m, d))

    @staticmethod
    def Dateabs(w, y, m, d):
        return Tok(TOK.DATEABS, w, (y, m, d))

    @staticmethod
    def Daterel(w, y, m, d):
        return Tok(TOK.DATEREL, w, (y, m, d))

    @staticmethod
    def Timestamp(w, y, mo, d, h, m, s):
        return Tok(TOK.TIMESTAMP, w, (y, mo, d, h, m, s))

    @staticmethod
    def Timestampabs(w, y, mo, d, h, m, s):
        return Tok(TOK.TIMESTAMPABS, w, (y, mo, d, h, m, s))

    @staticmethod
    def Timestamprel(w, y, mo, d, h, m, s):
        return Tok(TOK.TIMESTAMPREL, w, (y, mo, d, h, m, s))

    @staticmethod
    def Year(w, n):
        return Tok(TOK.YEAR, w, n)

    @staticmethod
    def Telno(w, telno, cc="354"):
        # The w parameter is the original token text,
        # while telno has the standard form 'DDD-DDDD' (with hyphen)
        # cc is the country code
        return Tok(TOK.TELNO, w, (telno, cc))

    @staticmethod
    def Email(w):
        return Tok(TOK.EMAIL, w, None)

    @staticmethod
    def Number(w, n, cases=None, genders=None):
        # The cases parameter is a list of possible cases for this number
        # (if it was originally stated in words)
        return Tok(TOK.NUMBER, w, (n, cases, genders))

    @staticmethod
    def NumberWithLetter(w, n, l):
        return Tok(TOK.NUMWLETTER, w, (n, l))

    @staticmethod
    def Currency(w, iso, cases=None, genders=None):
        # The cases parameter is a list of possible cases for this currency name
        # (if it was originally stated in words, i.e. not abbreviated)
        return Tok(TOK.CURRENCY, w, (iso, cases, genders))

    @staticmethod
    def Amount(w, iso, n, cases=None, genders=None):
        # The cases parameter is a list of possible cases for this amount
        # (if it was originally stated in words)
        return Tok(TOK.AMOUNT, w, (n, iso, cases, genders))

    @staticmethod
    def Percent(w, n, cases=None, genders=None):
        return Tok(TOK.PERCENT, w, (n, cases, genders))

    @staticmethod
    def Ordinal(w, n):
        return Tok(TOK.ORDINAL, w, n)

    @staticmethod
    def Url(w):
        return Tok(TOK.URL, w, None)

    @staticmethod
    def Domain(w):
        return Tok(TOK.DOMAIN, w, None)

    @staticmethod
    def Hashtag(w):
        return Tok(TOK.HASHTAG, w, None)

    @staticmethod
    def Ssn(w):
        return Tok(TOK.SSN, w, None)

    @staticmethod
    def Molecule(w):
        return Tok(TOK.MOLECULE, w, None)

    @staticmethod
    def Username(w, username):
        return Tok(TOK.USERNAME, w, username)

    @staticmethod
    def SerialNumber(w):
        return Tok(TOK.SERIALNUMBER, w, None)

    @staticmethod
    def Measurement(w, unit, val):
        return Tok(TOK.MEASUREMENT, w, (unit, val))

    @staticmethod
    def Word(w, m=None):
        # The m parameter is intended for a list of BIN_Meaning tuples
        # fetched from the BÍN database
        return Tok(TOK.WORD, w, m)

    @staticmethod
    def Unknown(w):
        return Tok(TOK.UNKNOWN, w, None)

    @staticmethod
    def Person(w, m=None):
        # The m parameter is intended for a list of PersonName tuples:
        # (name, gender, case)
        return Tok(TOK.PERSON, w, m)

    @staticmethod
    def Entity(w):
        return Tok(TOK.ENTITY, w, None)

    @staticmethod
    def Company(w):
        return Tok(TOK.COMPANY, w, None)

    @staticmethod
    def Begin_Paragraph():
        return Tok(TOK.P_BEGIN, None, None)

    @staticmethod
    def End_Paragraph():
        return Tok(TOK.P_END, None, None)

    @staticmethod
    def Begin_Sentence(num_parses=0, err_index=None):
        return Tok(TOK.S_BEGIN, None, (num_parses, err_index))

    @staticmethod
    def End_Sentence():
        return Tok(TOK.S_END, None, None)

    @staticmethod
    def End_Sentinel():
        return Tok(TOK.X_END, None, None)

    @staticmethod
    def Split_Sentence():
        return Tok(TOK.S_SPLIT, None, None)


def normalized_text(token):
    """ Returns token text after normalizing punctuation """
    return token.val[1] if token.kind == TOK.PUNCTUATION else token.txt


def text_from_tokens(tokens):
    """ Return text from a list of tokens, without normalization """
    return " ".join(t.txt for t in tokens if t.txt)


def normalized_text_from_tokens(tokens):
    """ Return text from a list of tokens, without normalization """
    return " ".join(filter(None, map(normalized_text, tokens)))


def is_valid_date(y, m, d):
    """ Returns True if y, m, d is a valid date """
    if (1776 <= y <= 2100) and (1 <= m <= 12) and (1 <= d <= DAYS_IN_MONTH[m]):
        try:
            datetime.datetime(year=y, month=m, day=d)
            return True
        except ValueError:
            pass
    return False


def parse_digits(w, convert_numbers):
    """ Parse a raw token starting with a digit """
    s = re.match(r"\d{1,2}:\d\d:\d\d,\d\d(?!\d)", w)
    if s:
        # Looks like a 24-hour clock with milliseconds, H:M:S:MS
        # TODO use millisecond information in token
        g = s.group()
        p = g.split(":")
        h = int(p[0])
        m = int(p[1])
        sec = int(p[2].split(",")[0])
        if (0 <= h < 24) and (0 <= m < 60) and (0 <= sec < 60):
            return TOK.Time(g, h, m, sec), s.end()

    s = re.match(r"\d{1,2}:\d\d:\d\d(?!\d)", w)
    if s:
        # Looks like a 24-hour clock, H:M:S
        g = s.group()
        p = g.split(":")
        h = int(p[0])
        m = int(p[1])
        sec = int(p[2])
        if (0 <= h < 24) and (0 <= m < 60) and (0 <= sec < 60):
            return TOK.Time(g, h, m, sec), s.end()

    s = re.match(r"\d{1,2}:\d\d(?!\d)", w)
    if s:
        # Looks like a 24-hour clock, H:M
        g = s.group()
        p = g.split(":")
        h = int(p[0])
        m = int(p[1])
        if (0 <= h < 24) and (0 <= m < 60):
            return TOK.Time(g, h, m, 0), s.end()

    s = re.match(r"((\d{4}-\d\d-\d\d)|(\d{4}/\d\d/\d\d))(?!\d)", w)
    if s:
        # Looks like an ISO format date: YYYY-MM-DD or YYYY/MM/DD
        g = s.group()
        if "-" in g:
            p = g.split("-")
        else:
            p = g.split("/")
        y = int(p[0])
        m = int(p[1])
        d = int(p[2])
        if is_valid_date(y, m, d):
            return TOK.Date(g, y, m, d), s.end()

    s = (
        re.match(r"\d{1,2}\.\d{1,2}\.\d{2,4}(?!\d)", w) or
        re.match(r"\d{1,2}/\d{1,2}/\d{2,4}(?!\d)", w) or
        re.match(r"\d{1,2}-\d{1,2}-\d{2,4}(?!\d)", w)
    )
    if s:
        # Looks like a date with day, month and year parts
        g = s.group()
        if "/" in g:
            p = g.split("/")
        elif "-" in g:
            p = g.split("-")
        else:
            p = g.split(".")
        y = int(p[2])
        if y <= 99:
            # 50 means 2050, but 51 means 1951
            y += 1900 if y > 50 else 2000
        m = int(p[1])
        d = int(p[0])
        if m > 12 >= d:
            # Probably wrong way (i.e. U.S. American way) around
            m, d = d, m
        if is_valid_date(y, m, d):
            return TOK.Date(g, y, m, d), s.end()

    s = re.match(r"(\d{2})\.(\d{2})(?!\d)", w)
    if s:
        # A date in the form dd.mm
        # (Allowing hyphens here would interfere with for instance
        # sports scores and phrases such as 'Það voru 10-12 manns þarna.')
        g = s.group()
        d = int(s.group(1))
        m = int(s.group(2))
        if (1 <= m <= 12) and (1 <= d <= DAYS_IN_MONTH[m]):
            return TOK.Daterel(g, y=0, m=m, d=d), s.end()

    s = re.match(r"(\d{2})[-.](\d{4})(?!\d)", w)
    if s:
        # A date in the form of mm.yyyy or mm-yyyy
        g = s.group()
        m = int(s.group(1))
        y = int(s.group(2))
        if (1776 <= y <= 2100) and (1 <= m <= 12):
            return TOK.Daterel(g, y=y, m=m, d=0), s.end()

    # Note: the following must use re.UNICODE to make sure that
    # \w matches all Icelandic characters under Python 2
    s = re.match(r"\d+([a-zA-Z])(?!\w)", w, re.UNICODE)
    if s:
        # Looks like a number with a single trailing character, e.g. 14b, 33C, 1122f
        g = s.group()
        l = g[-1:]
        # Only match if the single character is not a
        # unit of measurement (e.g. 'A', 'l', 'V')
        if l not in SI_UNITS_SET:
            n = int(g[:-1])
            return TOK.NumberWithLetter(g, n, l), s.end()

    s = NUM_WITH_UNIT_REGEX1.match(w)
    if s:
        # Icelandic-style number followed by an SI unit, or degree/percentage,
        # or currency symbol
        g = s.group()
        val = float(s.group(1).replace(".", "").replace(",", "."))
        unit = s.group(4)
        if unit in CURRENCY_SYMBOLS:
            # This is an amount with a currency symbol at the end
            iso = CURRENCY_SYMBOLS[unit]
            return TOK.Amount(g, iso, val), s.end()
        unit, factor = SI_UNITS[unit]
        if callable(factor):
            val = factor(val)
        else:
            # Simple scaling factor
            val *= factor
        if unit in ("%", "‰"):
            return TOK.Percent(g, val), s.end()
        return TOK.Measurement(g, unit, val), s.end()

    s = NUM_WITH_UNIT_REGEX2.match(w)
    if s:
        # English-style number followed by an SI unit, or degree/percentage,
        # or currency symbol
        g = s.group()
        val = float(s.group(1).replace(",", ""))
        unit = s.group(4)
        if unit in CURRENCY_SYMBOLS:
            # This is an amount with a currency symbol at the end
            iso = CURRENCY_SYMBOLS[unit]
            return TOK.Amount(g, iso, val), s.end()
        unit, factor = SI_UNITS[unit]
        if callable(factor):
            val = factor(val)
        else:
            # Simple scaling factor
            val *= factor
        if convert_numbers:
            g = re.sub(",", "x", g)  # Change thousands separator to 'x'
            g = re.sub(r"\.", ",", g)  # Change decimal separator to ','
            g = re.sub("x", ".", g)  # Change 'x' to '.'
        if unit in ("%", "‰"):
            return TOK.Percent(g, val), s.end()
        return TOK.Measurement(g, unit, val), s.end()

    s = NUM_WITH_UNIT_REGEX3.match(w)
    if s:
        # One or more digits, followed by a unicode
        # vulgar fraction char (e.g. '2½') and an SI unit,
        # percent/promille, or currency code
        g = s.group()
        ln = s.group(1)
        vf = s.group(2)
        orig_unit = s.group(3)
        value = float(ln) + unicodedata.numeric(vf)
        if orig_unit in CURRENCY_SYMBOLS:
            # This is an amount with a currency symbol at the end
            iso = CURRENCY_SYMBOLS[orig_unit]
            return TOK.Amount(g, iso, value), s.end()
        unit, factor = SI_UNITS[orig_unit]
        if callable(factor):
            value = factor(value)
        else:
            # Simple scaling factor
            value *= factor
        if unit in ("%", "‰"):
            return TOK.Percent(g, value), s.end()
        return TOK.Measurement(g, unit, value), s.end()

    s = re.match(r"(\d+)([\u00BC-\u00BE\u2150-\u215E])", w, re.UNICODE)
    if s:
        # One or more digits, followed by a unicode vulgar fraction char (e.g. '2½')
        g = s.group()
        ln = s.group(1)
        vf = s.group(2)
        val = float(ln) + unicodedata.numeric(vf)
        return TOK.Number(g, val), s.end()

    s = re.match(r"[\+\-]?\d+(\.\d\d\d)*,\d+(?!\d*\.\d)", w)  # Can't end with digits.digits
    if s:
        # Icelandic-style real number formatted with decimal comma (,)
        # and possibly thousands separators (.)
        # (we need to check this before checking integers)
        g = s.group()
        if re.match(r",\d+", w[len(g):]):
            # English-style thousand separator multiple times
            s = None
        else:
            n = re.sub(r"\.", "", g)  # Eliminate thousands separators
            n = re.sub(",", ".", n)  # Convert decimal comma to point
            return TOK.Number(g, float(n)), s.end()

    s = re.match(r"[\+\-]?\d+(\.\d\d\d)+(?!\d)", w)
    if s:
        # Integer with a '.' thousands separator
        # (we need to check this before checking dd.mm dates)
        g = s.group()
        n = re.sub(r"\.", "", g)  # Eliminate thousands separators
        return TOK.Number(g, int(n)), s.end()

    s = re.match(r"\d{1,2}/\d{1,2}(?!\d)", w)
    if s:
        # Looks like a date (and not something like 10/2007)
        g = s.group()
        p = g.split("/")
        m = int(p[1])
        d = int(p[0])
        if (
            p[0][0] != "0"
            and p[1][0] != "0"
            and ((d <= 5 and m <= 6) or (d == 1 and m <= 10))
        ):
            # This is probably a fraction, not a date
            # (1/2, 1/3, 1/4, 1/5, 1/6, 2/3, 2/5, 5/6 etc.)
            # Return a number
            return TOK.Number(g, float(d) / m), s.end()
        if m > 12 >= d:
            # Date is probably wrong way around
            m, d = d, m
        if (1 <= m <= 12) and (1 <= d <= DAYS_IN_MONTH[m]):
            # Looks like a (roughly) valid date
            return TOK.Daterel(g, y=0, m=m, d=d), s.end()

    s = re.match(r"\d\d\d\d(?!\d)", w)
    if s:
        n = int(s.group())
        if 1776 <= n <= 2100:
            # Looks like a year
            return TOK.Year(w[0:4], n), 4

    s = re.match(r"\d{6}\-\d{4}(?!\d)", w)
    if s:
        # Looks like a social security number
        g = s.group()
        if valid_ssn(g):
            return TOK.Ssn(w[0:11]), 11

    s = re.match(r"\d\d\d\-\d\d\d\d(?!\d)", w)
    if s and w[0] in TELNO_PREFIXES:
        # Looks like a telephone number
        telno = s.group()
        return TOK.Telno(telno, telno), 8
    if s:
        # Most likely some sort of serial number
        # Unknown token for now, don't want it separated
        return TOK.SerialNumber(s.group()), s.end()

    s = re.match(r"\d+\-\d+(\-\d+)+", w)
    if s:
        # Multi-component serial number
        return TOK.SerialNumber(s.group()), s.end()

    s = re.match(r"\d\d\d\d\d\d\d(?!\d)", w)
    if s and w[0] in TELNO_PREFIXES:
        # Looks like a telephone number
        telno = w[0:3] + "-" + w[3:7]
        return TOK.Telno(w[0:7], telno), 7

    s = re.match(r"\d+\.\d+(\.\d+)+", w)
    if s:
        # Some kind of ordinal chapter number: 2.5.1 etc.
        # (we need to check this before numbers with decimal points)
        g = s.group()
        # !!! TODO: A better solution would be to convert 2.5.1 to (2,5,1)
        n = re.sub(r"\.", "", g)  # Eliminate dots, 2.5.1 -> 251
        return TOK.Ordinal(g, int(n)), s.end()

    s = re.match(r"[\+\-]?\d+(,\d\d\d)*\.\d+", w)
    if s:
        # English-style real number with a decimal point (.),
        # and possibly commas as thousands separators (,)
        g = s.group()
        n = re.sub(",", "", g)  # Eliminate thousands separators
        # !!! TODO: May want to mark this as an error
        if convert_numbers:
            g = re.sub(",", "x", g)  # Change thousands separator to 'x'
            g = re.sub(r"\.", ",", g)  # Change decimal separator to ','
            g = re.sub("x", ".", g)  # Change 'x' to '.'
        return TOK.Number(g, float(n)), s.end()

    s = re.match(r"[\+\-]?\d+(,\d\d\d)*(?!\d)", w)
    if s:
        # Integer, possibly with a ',' thousands separator
        g = s.group()
        n = re.sub(",", "", g)  # Eliminate thousands separators
        # !!! TODO: May want to mark this as an error
        if convert_numbers:
            g = re.sub(",", ".", g)  # Change thousands separator to a dot
        return TOK.Number(g, int(n)), s.end()

    # Strange thing
    # !!! TODO: May want to mark this as an error
    return TOK.Unknown(w), len(w)


def gen_from_string(txt, replace_composite_glyphs=True):
    """ Generate rough tokens from a string """
    if replace_composite_glyphs:
        # Replace composite glyphs with single code points
        txt = UNICODE_REGEX.sub(
            lambda match: UNICODE_REPLACEMENTS[match.group(0)], txt,
        )
    # If there are consecutive newlines in the string (i.e. two
    # newlines separated only by whitespace), we interpret
    # them as hard sentence boundaries
    first = True
    for span in re.split(r"\n\s*\n", txt):
        if first:
            first = False
        else:
            # Return a sentence splitting token in lieu of the
            # newline pair that separates the spans
            yield ""
        for w in span.split():
            yield w


def gen(text_or_gen, replace_composite_glyphs=True):
    """ Generate rough tokens from a string or a generator """
    if text_or_gen is None:
        return
    if is_str(text_or_gen):
        # The parameter is a single string: wrap it in an iterable
        text_or_gen = [text_or_gen]
    # Iterate through text_or_gen, which is assumed to yield strings
    for txt in text_or_gen:
        txt = txt.strip()
        if not txt:
            # Empty line: signal this to the consumer of the generator
            yield ""
        else:
            # Convert to a Unicode string (if Python 2.7)
            txt = make_str(txt)
            # Yield the contained rough tokens
            for w in gen_from_string(txt, replace_composite_glyphs):
                yield w


def could_be_end_of_sentence(next_token, test_set=TOK.TEXT, multiplier=False):
    """ Return True if next_token could be ending the current sentence or
        starting the next one """
    return (
        next_token.kind in TOK.END
        or (
            # Check whether the next token is an uppercase word, except if
            # it is a month name (frequently misspelled in uppercase) or
            # roman numeral, or a currency abbreviation if preceded by a
            # multiplier (for example þ. USD for thousands of USD)
            next_token.kind in test_set
            and next_token.txt[0].isupper()
            and next_token.txt.lower() not in MONTHS
            and not RE_ROMAN_NUMERAL.match(next_token.txt)
            and not (next_token.txt in CURRENCY_ABBREV and multiplier)
        )
    )


def parse_tokens(txt, **options):
    """ Generator that parses contiguous text into a stream of tokens """

    # Obtain individual flags from the options dict
    convert_numbers = options.get("convert_numbers", False)
    replace_composite_glyphs = options.get("replace_composite_glyphs", True)

    # The default behavior for kludgy ordinals is to pass them
    # through as word tokens
    handle_kludgy_ordinals = options.get(
        "handle_kludgy_ordinals", KLUDGY_ORDINALS_PASS_THROUGH
    )

    # This code proceeds roughly as follows:
    # 1) The text is split into raw tokens on whitespace boundaries.
    # 2) (By far the most common case:) Raw tokens that are purely
    #    alphabetic are yielded as word tokens.
    # 3) Punctuation from the front of the remaining raw token is identified
    #    and yielded. A special case applies for quotes.
    # 4) A set of checks is applied to the rest of the raw token, identifying
    #    tokens such as e-mail addresses, domains and @usernames. These can
    #    start with digits, so the checks must occur before step 5.
    # 5) Tokens starting with a digit (eventually preceded
    #    by a + or - sign) are sent off to a separate function that identifies
    #    integers, real numbers, dates, telephone numbers, etc. via regexes.
    # 6) After such checks, alphabetic sequences (words) at the start of the
    #    raw token are identified. Such a sequence can, by the way, also
    #    contain embedded apostrophes and hyphens (Dunkin' Donuts, Mary's,
    #    marg-ítrekaðri).
    # 7) The process is repeated from step 4) until the current raw token is
    #    exhausted. At that point, we obtain the next token and start from 2).

    for w in gen(txt, replace_composite_glyphs):

        # Handle each sequence w of non-whitespace characters

        if not w:
            # An empty string signals an empty line, which splits sentences
            yield TOK.Split_Sentence()
            continue

        if w.isalpha() or w in SI_UNITS:
            # Shortcut for most common case: pure word
            yield TOK.Word(w)
            continue

        if len(w) > 1:
            if w[0] in SIGN_PREFIX and w[1] in DIGITS_PREFIX:
                # Digit, preceded by sign (+/-): parse as a number
                # Note that we can't immediately parse a non-signed number
                # here since kludges such as '3ja' and domain names such as '4chan.com'
                # need to be handled separately below
                t, eaten = parse_digits(w, convert_numbers)
                yield t
                w = w[eaten:]
                if not w:
                    continue
            elif w[0] in COMPOSITE_HYPHENS and w[1].isalpha():
                # This may be something like '-menn' in 'þingkonur og -menn'
                i = 2
                while i < len(w) and w[i].isalpha():
                    i += 1
                yield TOK.Word(w[:i])
                w = w[i:]

        # Shortcut for quotes around a single word
        if len(w) >= 3:
            if w[0] in DQUOTES and w[-1] in DQUOTES:
                # Convert to matching Icelandic quotes
                # yield TOK.Punctuation("„")
                if w[1:-1].isalpha():
                    yield TOK.Punctuation(w[0], normalized="„")
                    yield TOK.Word(w[1:-1])
                    yield TOK.Punctuation(w[-1], normalized="“")
                    continue
            elif w[0] in SQUOTES and w[-1] in SQUOTES:
                # Convert to matching Icelandic quotes
                # yield TOK.Punctuation("‚")
                if w[1:-1].isalpha():
                    yield TOK.Punctuation(w[0], normalized="‚")
                    yield TOK.Word(w[1:-1])
                    yield TOK.Punctuation(w[-1], normalized="‘")
                    continue

        # Special case for leading quotes, which are interpreted
        # as opening quotes
        if len(w) > 1:
            if w[0] in DQUOTES:
                # Convert simple quotes to proper opening quotes
                yield TOK.Punctuation(w[0], normalized="„")
                w = w[1:]
            elif w[0] in SQUOTES:
                # Convert simple quotes to proper opening quotes
                yield TOK.Punctuation(w[0], normalized="‚")
                w = w[1:]

        # More complex case of mixed punctuation, letters and numbers
        while w:
            # Handle punctuation
            ate = False
            while w and w[0] in PUNCTUATION:
                ate = True
                lw = len(w)
                if w.startswith("[...]"):
                    yield TOK.Punctuation("[...]", normalized="[…]")
                    w = w[5:]
                elif w.startswith("[…]"):
                    yield TOK.Punctuation("[…]")
                    w = w[3:]
                elif w.startswith("..."):
                    # Treat ellipsis as one piece of punctuation
                    dots = "..."
                    wdots = w[3:]
                    while wdots.startswith("."):
                        dots += "."
                        wdots = wdots[1:]
                    yield TOK.Punctuation(dots, normalized="…")
                    w = wdots
                elif w.startswith("…"):
                    # Treat ellipsis as one piece of punctuation
                    dots = "…"
                    wdots = w[1:]
                    while wdots.startswith("…"):
                        dots += "…"
                        wdots = wdots[1:]
                    yield TOK.Punctuation(dots, normalized="…")
                    # TODO LAGA Hér ætti að safna áfram.
                    w = wdots
                # TODO STILLING Was at the end of a word or by itself, should be ",".
                # Won't correct automatically, check for M6
                elif w == ",,":
                    yield TOK.Punctuation(",,", normalized=",")
                    w = ""
                # TODO STILLING kommum í upphafi orðs breytt í gæsalappir
                elif w.startswith(",,"):
                    # Probably an idiot trying to type opening double quotes with commas
                    yield TOK.Punctuation(",,", normalized="„")
                    w = w[2:]
                elif lw == 2 and (w == "[[" or w == "]]"):
                    # Begin or end paragraph marker
                    if w == "[[":
                        yield TOK.Begin_Paragraph()
                    else:
                        yield TOK.End_Paragraph()
                    w = w[2:]
                elif w[0] in HYPHENS:
                    # Normalize all hyphens the same way
                    yield TOK.Punctuation(w[0], normalized=HYPHEN)
                    w = w[1:]
                elif w[0] in DQUOTES:
                    # Convert to a proper closing double quote
                    yield TOK.Punctuation(w[0], normalized="“")
                    w = w[1:]
                elif w[0] in SQUOTES:
                    # Left with a single quote, convert to proper closing quote
                    yield TOK.Punctuation(w[0], normalized="‘")
                    w = w[1:]
                elif lw > 1 and w.startswith("#"):
                    # Might be a hashtag, processed later
                    ate = False
                    break
                elif lw > 1 and w.startswith("@"):
                    # Username on Twitter or other social media platforms
                    s = re.match(r"\@[0-9a-z_]+", w)
                    if s:
                        g = s.group()
                        yield TOK.Username(g, g[1:])
                        w = w[s.end():]
                    else:
                        yield TOK.Punctuation("@")
                        w = w[1:]
                else:
                    yield TOK.Punctuation(w[0])
                    w = w[1:]

            # End of punctuation loop
            # Check for specific token types other than punctuation

            if w and "@" in w:
                # Check for valid e-mail
                # Note: we don't allow double quotes (simple or closing ones) in e-mails here
                # even though they're technically allowed according to the RFCs
                s = re.match(r"[^@\s]+@[^@\s]+(\.[^@\s\.,/:;\"\(\)%#!\?”]+)+", w)
                if s:
                    ate = True
                    yield TOK.Email(s.group())
                    w = w[s.end() :]

            # Unicode single-char vulgar fractions
            # TODO: Support multiple-char unicode fractions that
            # use super/subscript w. DIVISION SLASH (U+2215)
            if w and w[0] in SINGLECHAR_FRACTIONS:
                ate = True
                yield TOK.Number(w[0], unicodedata.numeric(w[0]))
                w = w[1:]

            if w and w.startswith(URL_PREFIXES):
                # Handle URL: cut RIGHT_PUNCTUATION characters off its end,
                # even though many of them are actually allowed according to
                # the IETF RFC
                endp = ""
                while w and w[-1] in RIGHT_PUNCTUATION:
                    endp = w[-1] + endp
                    w = w[:-1]
                yield TOK.Url(w)
                ate = True
                w = endp

            if w and len(w) >= 2 and re.match(r"#\w", w, re.UNICODE):
                # Handle hashtags. Eat all text up to next punctuation character
                # so we can handle strings like "#MeToo-hreyfingin" as two words
                tag = w[:1]
                w = w[1:]
                while w and w[0] not in PUNCTUATION:
                    tag += w[0]
                    w = w[1:]
                if re.match(r"#\d+$", tag):
                    # Hash is being used as a number sign, e.g. "#12"
                    yield TOK.Ordinal(tag, int(tag[1:]))
                else:
                    yield TOK.Hashtag(tag)
                ate = True

            # Domain name (e.g. greynir.is)
            if (
                w
                and len(w) >= MIN_DOMAIN_LENGTH
                and w[0].isalnum()  # All domains start with an alphanumeric char
                and "." in w[1:-2]  # Optimization, TLD is at least 2 chars
                and DOMAIN_REGEX.search(w)
            ):
                endp = ""
                while w and w[-1] in PUNCTUATION:
                    endp = w[-1] + endp
                    w = w[:-1]
                yield TOK.Domain(w)
                ate = True
                w = endp

            # Numbers or other stuff starting with a digit
            # (eventually prefixed by a '+' or '-')
            if w and (
                w[0] in DIGITS_PREFIX
                or (w[0] in SIGN_PREFIX and len(w) >= 2 and w[1] in DIGITS_PREFIX)
            ):
                # Handle kludgy ordinals: '3ji', '5ti', etc.
                for key, val in items(ORDINAL_ERRORS):
                    if w.startswith(key):
                        # This is a kludgy ordinal
                        if handle_kludgy_ordinals == KLUDGY_ORDINALS_MODIFY:
                            # Convert ordinals to corresponding word tokens:
                            # '1sti' -> 'fyrsti', '3ji' -> 'þriðji', etc.
                            yield TOK.Word(val)
                        elif (
                            handle_kludgy_ordinals == KLUDGY_ORDINALS_TRANSLATE
                            and key in ORDINAL_NUMBERS
                        ):
                            # Convert word-form ordinals into ordinal tokens,
                            # i.e. '1sti' -> TOK.Ordinal('1sti', 1),
                            # but leave other kludgy constructs ('2ja')
                            # as word tokens
                            yield TOK.Ordinal(key, ORDINAL_NUMBERS[key])
                        else:
                            # No special handling of kludgy ordinals:
                            # yield them unchanged as word tokens
                            yield TOK.Word(key)
                        eaten = len(key)
                        break  # This skips the for loop 'else'
                else:
                    # Not a kludgy ordinal: eat tokens starting with a digit
                    t, eaten = parse_digits(w, convert_numbers)
                    yield t
                # Continue where the digits parser left off
                ate = True
                w = w[eaten:]

                if w:
                    # Check for an SI unit immediately following a number
                    r = SI_UNITS_REGEX.match(w)
                    if r:
                        unit = r.group()
                        # Handle the case where a measurement unit is
                        # immediately following a number, without an intervening space
                        # (note that some of them contain nonalphabetic characters,
                        # so they won't be caught by the isalpha() check below)
                        yield TOK.Word(unit)
                        w = w[len(unit):]

            # Check for molecular formula ('H2SO4')
            if w:
                r = MOLECULE_REGEX.match(w)
                if r is not None:
                    g = r.group()
                    if g not in Abbreviations.DICT and MOLECULE_FILTER.search(g):
                        # Correct format, containing at least one digit
                        # and not separately defined as an abbreviation:
                        # We assume that this is a molecular formula
                        yield TOK.Molecule(g)
                        ate = True
                        w = w[r.end():]

            # Check for currency abbreviations immediately followed by a number
            if w and len(w) > 3 and w[0:3] in CURRENCY_ABBREV and w[3].isdigit():
                t, eaten = parse_digits(w[3:], convert_numbers)
                if t.kind == TOK.NUMBER:
                    yield(
                        TOK.Amount(
                            w[:3+eaten], w[:3], t.val[0]
                        )
                    )
                    ate = True
                    w = w[3+eaten:]

            # Alphabetic characters
            # (or a hyphen immediately followed by alphabetic characters,
            # such as in 'þingkonur og -menn')
            if w and w[0].isalpha():
                ate = True
                lw = len(w)
                i = 1
                while i < lw and (
                    w[i].isalpha()
                    or (
                        w[i] in PUNCT_INSIDE_WORD
                        and i + 1 < lw
                        and w[i + 1].isalpha()
                    )
                ):
                    # We allow dots to occur inside words in the case of
                    # abbreviations; also apostrophes are allowed within
                    # words and at the end (albeit not consecutively)
                    # (O'Malley, Mary's, it's, childrens', O‘Donnell).
                    # The same goes for ² and ³
                    i += 1
                if i < lw and w[i] in PUNCT_ENDING_WORD:
                    i += 1
                # Make a special check for the occasional erroneous source text
                # case where sentences run together over a period without a space:
                # 'sjávarútvegi.Það'
                # TODO STILLING Viljum merkja sem villu fyrir málrýni, og hafa
                # sem mögulega stillingu.
                ww = w[0:i]
                a = ww.split(".")
                if (
                    len(a) == 2
                    # First part must be more than one letter for us to split
                    and len(a[0]) > 1
                    # The first part may start with an uppercase or lowercase letter
                    # but the rest of it must be lowercase
                    and a[0][1:].islower()
                    and a[1]
                    # The second part must start with an uppercase letter
                    and a[1][0].isupper()
                    # Corner case: an abbrev such as 'f.Kr' should not be split
                    and w[0:i+1] not in Abbreviations.DICT
                ):
                    # We have a lowercase word immediately followed by a period
                    # and an uppercase word
                    yield TOK.Word(a[0])
                    yield TOK.Punctuation(".")
                    yield TOK.Word(a[1])
                else:
                    if ww.endswith("-og") or ww.endswith("-eða"):
                        # Handle missing space before 'og'/'eða',
                        # such as 'fjármála-og efnahagsráðuneyti'
                        a = ww.split("-")
                        yield TOK.Word(a[0])
                        yield TOK.Punctuation("-", normalized=COMPOSITE_HYPHEN)
                        yield TOK.Word(a[1])
                    else:
                        yield TOK.Word(ww)
                w = w[i:]
                if w and w[0] in COMPOSITE_HYPHENS:
                    # This is a hyphen or en dash directly appended to a word:
                    # might be a continuation ('fjármála- og efnahagsráðuneyti')
                    # Yield a special hyphen as a marker
                    yield TOK.Punctuation(w[0], normalized=COMPOSITE_HYPHEN)
                    w = w[1:]

            # Special case for quotes attached on the right hand side to other stuff,
            # assumed to be closing quotes rather than opening ones
            if w:
                if w[0] in SQUOTES:
                    yield TOK.Punctuation(w[0], normalized="‘")
                    w = w[1:]
                    ate = True
                elif w[0] in DQUOTES:
                    yield TOK.Punctuation(w[0], normalized="“")
                    w = w[1:]
                    ate = True

            if not ate:
                # Ensure that we eat everything, even unknown stuff
                yield TOK.Unknown(w[0])
                w = w[1:]

    # Yield a sentinel token at the end that will be cut off by the final generator
    yield TOK.End_Sentinel()


def parse_particles(token_stream, **options):
    """ Parse a stream of tokens looking for 'particles'
        (simple token pairs and abbreviations) and making substitutions """

    convert_measurements = options.pop("convert_measurements", False)

    def is_abbr_with_period(txt):
        """ Return True if the given token text is an abbreviation
            when followed by a period """
        if "." in txt:
            # There is already a period in it: must be an abbreviation
            # (this applies for instance to "t.d" but not to "mbl.is")
            return True
        if txt in Abbreviations.SINGLES:
            # The token's literal text is defined as an abbreviation
            # followed by a single period
            return True
        if txt.lower() in Abbreviations.SINGLES:
            # The token is in upper or mixed case:
            # We allow it as an abbreviation unless the exact form
            # (most often uppercase) is an abbreviation that doesn't
            # require a period (i.e. isn't in SINGLES).
            # This applies for instance to DR which means
            # "Danmark's Radio" instead of "doktor" (dr.)
            return txt not in Abbreviations.DICT
        return False

    def lookup(abbrev):
        """ Look up an abbreviation, both in original case and in lower case,
            and return either None if not found or a meaning list having one entry """
        m = Abbreviations.DICT.get(abbrev)
        if not m:
            m = Abbreviations.DICT.get(abbrev.lower())
        return list(m) if m else None

    token = None
    try:
        # Maintain a one-token lookahead
        token = next(token_stream)
        while True:
            next_token = next(token_stream)
            # Make the lookahead checks we're interested in
            # Check for currency symbol followed by number, e.g. $10
            if token.txt in CURRENCY_SYMBOLS:
                for symbol, currabbr in items(CURRENCY_SYMBOLS):
                    if (
                        token.kind == TOK.PUNCTUATION
                        and token.txt == symbol
                        and next_token.kind == TOK.NUMBER
                    ):
                        token = TOK.Amount(
                            token.txt + next_token.txt, currabbr, next_token.val[0]
                        )
                        next_token = next(token_stream)
                        break

            # Special case for a DATEREL token of the form "25.10.",
            # i.e. with a trailing period: It can end a sentence
            if token.kind == TOK.DATEREL and "." in token.txt:
                if next_token.txt == ".":
                    next_next_token = next(token_stream)
                    if could_be_end_of_sentence(next_next_token):
                        # This is something like 'Ég fæddist 25.9. Það var gaman.'
                        yield token
                        token = next_token
                    else:
                        # This is something like 'Ég fæddist 25.9. í Svarfaðardal.'
                        y, m, d = token.val
                        token = TOK.Daterel(token.txt + ".", y, m, d)
                    next_token = next_next_token

            # Coalesce abbreviations ending with a period into a single
            # abbreviation token
            if next_token.kind == TOK.PUNCTUATION and next_token.val[1] == ".":
                if (
                    token.kind == TOK.WORD
                    and token.txt[-1] != "."
                    and is_abbr_with_period(token.txt)
                ):
                    # Abbreviation ending with period: make a special token for it
                    # and advance the input stream
                    follow_token = next(token_stream)
                    abbrev = token.txt + "."

                    # Check whether we might be at the end of a sentence, i.e.
                    # the following token is an end-of-sentence or end-of-paragraph,
                    # or uppercase (and not a month name misspelled in upper case).

                    if abbrev in Abbreviations.NAME_FINISHERS:
                        # For name finishers (such as 'próf.') we don't consider a
                        # following person name as an indicator of an end-of-sentence
                        # !!! TODO: This does not work as intended because person names
                        # !!! have not been recognized at this phase in the token pipeline.
                        # TODO JAÐAR Skoða þetta betur í jaðartilvikum.
                        test_set = TOK.TEXT_EXCL_PERSON
                    else:
                        test_set = TOK.TEXT

                    # TODO STILLING í MONTHS eru einhverjar villur eins og "septembers",
                    # þær þarf að vera hægt að sameina í þessa flóknari tóka en viljum
                    # geta merkt það sem villu. Ætti líklega að setja í sérlista,
                    # WRONG_MONTHS, og sérif-lykkju og setja inn villu í tókann.
                    finish = could_be_end_of_sentence(
                        follow_token, test_set, abbrev in MULTIPLIERS
                    )
                    if finish:
                        # Potentially at the end of a sentence
                        if abbrev in Abbreviations.FINISHERS:
                            # We see this as an abbreviation even if the next sentence
                            # seems to be starting just after it.
                            # Yield the abbreviation without a trailing dot,
                            # and then an 'extra' period token to end the current sentence.
                            token = TOK.Word(token.txt, lookup(abbrev))
                            yield token
                            # Set token to the period
                            token = next_token
                        elif abbrev in Abbreviations.NOT_FINISHERS:
                            # This is a potential abbreviation that we don't interpret
                            # as such if it's at the end of a sentence
                            # ('dags.', 'próf.', 'mín.')
                            yield token
                            token = next_token
                        else:
                            # Substitute the abbreviation and eat the period
                            token = TOK.Word(abbrev, lookup(abbrev))
                    else:
                        # 'Regular' abbreviation in the middle of a sentence:
                        # Eat the period and yield the abbreviation as a single token
                        token = TOK.Word(abbrev, lookup(abbrev))

                    next_token = follow_token

            # Coalesce 'klukkan'/[kl.] + time or number into a time
            if next_token.kind == TOK.TIME or next_token.kind == TOK.NUMBER:
                if token.kind == TOK.WORD and token.txt.lower() in CLOCK_ABBREVS:
                    # Match: coalesce and step to next token
                    txt = token.txt
                    if next_token.kind == TOK.NUMBER:
                        # next_token.txt may be a real number, i.e. 13,40,
                        # which may have been converted from 13.40
                        # If we now have hh.mm, parse it as such
                        a = "{0:.2f}".format(next_token.val[0]).split(".")
                        h, m = int(a[0]), int(a[1])
                        token = TOK.Time(txt + " " + next_token.txt, h, m, 0)
                    else:
                        # next_token.kind is TOK.TIME
                        token = TOK.Time(
                            txt + " " + next_token.txt,
                            next_token.val[0],
                            next_token.val[1],
                            next_token.val[2],
                        )
                    next_token = next(token_stream)

            # Coalesce 'klukkan/kl. átta/hálfátta' into a time
            elif next_token.kind == TOK.WORD and next_token.txt.lower() in CLOCK_NUMBERS:
                if token.kind == TOK.WORD and token.txt.lower() in CLOCK_ABBREVS:
                    txt = token.txt
                    # Match: coalesce and step to next token
                    token = TOK.Time(
                        txt + " " + next_token.txt, *CLOCK_NUMBERS[next_token.txt.lower()]
                    )
                    next_token = next(token_stream)

            # Coalesce 'klukkan/kl. hálf átta' into a time
            elif next_token.kind == TOK.WORD and next_token.txt.lower() == "hálf":
                if token.kind == TOK.WORD and token.txt.lower() in CLOCK_ABBREVS:
                    time_token = next(token_stream)
                    time_txt = time_token.txt.lower()
                    if time_txt in CLOCK_NUMBERS and not time_txt.startswith("hálf"):
                        # Match
                        token = TOK.Time(
                            token.txt + " " + next_token.txt + " " + time_token.txt,
                            *CLOCK_NUMBERS["hálf" + time_txt]
                        )
                        next_token = next(token_stream)
                    else:
                        # Not a match: must retreat
                        yield token
                        token = next_token
                        next_token = time_token

            # Words like 'hálftólf' are only used in temporal expressions
            # so can stand alone
            if token.txt in CLOCK_HALF:
                token = TOK.Time(token.txt, *CLOCK_NUMBERS[token.txt])

            # Coalesce 'árið' + [year|number] into year
            if (token.kind == TOK.WORD and token.txt.lower() in YEAR_WORD) and (
                next_token.kind == TOK.YEAR or next_token.kind == TOK.NUMBER
            ):
                token = TOK.Year(
                    token.txt + " " + next_token.txt,
                    next_token.val
                    if next_token.kind == TOK.YEAR
                    else next_token.val[0],
                )
                next_token = next(token_stream)

            # Coalesece 3-digit number followed by 4-digit number into tel. no.
            if (
                token.kind == TOK.NUMBER
                and (next_token.kind == TOK.NUMBER or next_token.kind == TOK.YEAR)
                and token.txt[0] in TELNO_PREFIXES
                and re.search(r"^\d\d\d$", token.txt)
                and re.search(r"^\d\d\d\d$", next_token.txt)
            ):
                w = token.txt + " " + next_token.txt
                telno = token.txt + "-" + next_token.txt
                token = TOK.Telno(w, telno)
                next_token = next(token_stream)

            # Coalesce percentages or promilles into a single token
            if next_token.kind == TOK.PUNCTUATION and next_token.val[1] in ("%", "‰"):
                if token.kind == TOK.NUMBER:
                    # Percentage: convert to a single 'tight' percentage token
                    # In this case, there are no cases and no gender
                    sign = next_token.txt
                    # Store promille as one-tenth of a percentage
                    factor = 1.0 if sign == "%" else 0.1
                    token = TOK.Percent(token.txt + " " + sign, token.val[0] * factor)
                    next_token = next(token_stream)

            # Coalesce ordinals (1. = first, 2. = second...) into a single token
            if next_token.kind == TOK.PUNCTUATION and next_token.val[1] == ".":
                if (
                    token.kind == TOK.NUMBER
                    and not ("." in token.txt or "," in token.txt)
                ) or (
                    token.kind == TOK.WORD
                    and RE_ROMAN_NUMERAL.match(token.txt)
                    # Don't interpret a known abbreviation as a Roman numeral,
                    # for instance the newspaper 'DV'
                    and token.txt not in Abbreviations.DICT
                ):
                    # Ordinal, i.e. whole number or Roman numeral followed by period:
                    # convert to an ordinal token
                    follow_token = next(token_stream)
                    if (
                        follow_token.kind in TOK.END
                        or (
                            follow_token.kind == TOK.PUNCTUATION
                            and follow_token.val[1] in {"„", '"'}
                        )
                        or (
                            follow_token.kind == TOK.WORD
                            and follow_token.txt[0].isupper()
                            and month_for_token(follow_token, True) is None
                        )
                    ):
                        # Next token is a sentence or paragraph end, or opening quotes,
                        # or an uppercase word (and not a month name misspelled in
                        # upper case): fall back from assuming that this is an ordinal
                        yield token  # Yield the number or Roman numeral
                        token = next_token  # The period
                        # The following (uppercase) word or sentence end
                        next_token = follow_token
                    else:
                        # OK: replace the number/Roman numeral and the period
                        # with an ordinal token
                        num = (
                            token.val[0]
                            if token.kind == TOK.NUMBER
                            else roman_to_int(token.txt)
                        )
                        token = TOK.Ordinal(token.txt + ".", num)
                        # Continue with the following word
                        next_token = follow_token

            # Convert "1920 mm" or "30 °C" to a single measurement token
            if (
                token.kind == TOK.NUMBER or token.kind == TOK.YEAR
            ) and next_token.txt in SI_UNITS:

                value = token.val[0] if token.kind == TOK.NUMBER else token.val
                orig_unit = next_token.txt
                unit, factor = SI_UNITS[orig_unit]
                if callable(factor):
                    # We have a lambda conversion function
                    value = factor(value)
                else:
                    # Simple scaling factor
                    value *= factor
                if unit in ("%", "‰"):
                    token = TOK.Percent(token.txt + " " + next_token.txt, value)
                else:
                    token = TOK.Measurement(
                        token.txt + " " + next_token.txt, unit, value
                    )
                next_token = next(token_stream)

                # Special case for km/klst.
                if (
                    token.kind == TOK.MEASUREMENT
                    and orig_unit == "km"
                    and next_token.txt == "/"
                ):
                    slashtok = next_token
                    next_token = next(token_stream)
                    if next_token.txt == "klst":
                        unit = token.txt + "/" + next_token.txt
                        token = TOK.Measurement(unit, unit, value)
                        # Eat extra unit
                        next_token = next(token_stream)
                    else:
                        yield token
                        token = slashtok

            if (
                token.kind == TOK.MEASUREMENT
                and token.val[0] == "°"
                and next_token.kind == TOK.WORD
                and next_token.txt in {"C", "F", "K"}
            ):
                # Handle 200° C
                new_unit = "°" + next_token.txt
                unit, factor = SI_UNITS[new_unit]
                if callable(factor):
                    val = factor(token.val[1])
                else:
                    val = factor * token.val[1]

                if convert_measurements:    
                    token = TOK.Measurement(
                        token.txt[:-1] + " " + new_unit,  # 200 °C
                        unit,  # K
                        val,  # 200 converted to Kelvin
                    )
                else:
                    token = TOK.Measurement(
                        token.txt + " " + next_token.txt,  # 200° C
                        unit,  # K
                        val,  # 200 converted to Kelvin
                    )

                next_token = next(token_stream)

            # Special case for measurement abbreviations
            # erroneously ending with a period.
            # We only allow this for measurements that end with
            # an alphabetic character, i.e. not for ², ³, °, %, ‰.
            # [ Uncomment the last condition for this behavior:
            # We don't do this for measurement units which
            # have other meanings - such as 'gr' (grams), as
            # 'gr.' is probably the abbreviation for 'grein'. ]
            if (
                token.kind == TOK.MEASUREMENT
                and next_token.kind == TOK.PUNCTUATION 
                and next_token.txt == "."
                and token.txt[-1].isalpha()
                # and token.txt.split()[-1] + "." not in Abbreviations.DICT
            ):
                puncttoken = next_token
                next_token = next(token_stream)
                if could_be_end_of_sentence(next_token):
                    # We are at the end of the current sentence; back up
                    yield token
                    token = puncttoken
                else:
                    unit, value = token.val
                    # Add the period to the token text
                    token = TOK.Measurement(
                        token.txt + ".", unit, value
                    )

            # Cases such as USD. 44
            if (
                token.txt in CURRENCY_ABBREV
                and next_token.kind == TOK.PUNCTUATION
                and next_token.txt == "."
            ):
                puncttoken = next_token
                next_token = next(token_stream)
                if could_be_end_of_sentence(next_token):
                    # We are at the end of the current sentence; back up
                    yield token
                    token = puncttoken
                else:
                    token = TOK.Currency(
                        token.txt + ".", token.txt
                    )

            # Cases such as 19 $, 199.99 $
            if (
                token.kind == TOK.NUMBER
                and next_token.kind == TOK.PUNCTUATION
                and next_token.txt in CURRENCY_SYMBOLS
            ):
                token = TOK.Amount(
                    token.txt + " " + next_token.txt,
                    CURRENCY_SYMBOLS[next_token.txt],
                    token.val[0]
                )
                next_token = next(token_stream)

            # Replace straight abbreviations
            # (i.e. those that don't end with a period)
            if token.kind == TOK.WORD and token.val is None:
                if Abbreviations.has_meaning(token.txt):
                    # Add a meaning to the token
                    token = TOK.Word(token.txt, Abbreviations.get_meaning(token.txt))

            # Yield the current token and advance to the lookahead
            yield token
            token = next_token

    except StopIteration:
        # Final token (previous lookahead)
        if token:
            yield token


def parse_sentences(token_stream):
    """ Parse a stream of tokens looking for sentences, i.e. substreams within
        blocks delimited by sentence finishers (periods, question marks,
        exclamation marks, etc.) """

    in_sentence = False
    token = None
    tok_begin_sentence = TOK.Begin_Sentence()
    tok_end_sentence = TOK.End_Sentence()

    try:

        # Maintain a one-token lookahead
        token = next(token_stream)
        while True:
            next_token = next(token_stream)
            if token.kind == TOK.P_BEGIN or token.kind == TOK.P_END:
                # Block start or end: finish the current sentence, if any
                if in_sentence:
                    yield tok_end_sentence
                    in_sentence = False
                if token.kind == TOK.P_BEGIN and next_token.kind == TOK.P_END:
                    # P_BEGIN immediately followed by P_END: skip both and continue
                    # The double assignment to token is necessary to ensure that
                    # we are in a correct state if next() raises StopIteration
                    token = None
                    token = next(token_stream)
                    continue
            elif token.kind == TOK.X_END:
                assert not in_sentence
            elif token.kind == TOK.S_SPLIT:
                # Empty line in input: make sure to finish the current
                # sentence, if any, even if no ending punctuation has
                # been encountered
                if in_sentence:
                    yield tok_end_sentence
                in_sentence = False
                # Swallow the S_SPLIT token
                token = next_token
                continue
            else:
                if not in_sentence:
                    # This token starts a new sentence
                    yield tok_begin_sentence
                    in_sentence = True
                if (
                    token.kind == TOK.PUNCTUATION 
                    and token.val[1] in END_OF_SENTENCE
                    and not (
                        token.val[1] == "…"     # Excluding sentences with ellipsis in the middle
                        and not could_be_end_of_sentence(next_token)    
                    )
                ):
                    # Combining punctuation ('??!!!')
                    while (
                        token.val[1] in PUNCT_COMBINATIONS
                        and next_token.txt in PUNCT_COMBINATIONS
                    ):
                        # The normalized form comes from the first token except with "…?"
                        v = token.val[1]
                        if token.val[1] == "…" and next_token.val[1] == "?":
                            v = next_token.val[1]
                        next_token = TOK.Punctuation(token.txt+next_token.txt, v)
                        token = next_token
                        next_token = next(token_stream)
                    # We may be finishing a sentence with not only a period but also
                    # right parenthesis and quotation marks
                    while (
                        next_token.kind == TOK.PUNCTUATION
                        and next_token.val[1] in SENTENCE_FINISHERS
                    ):
                        yield token
                        token = next_token
                        next_token = next(token_stream)
                    # The sentence is definitely finished now
                    yield token
                    token = tok_end_sentence
                    in_sentence = False

            yield token
            token = next_token

    except StopIteration:
        pass

    # Final token (previous lookahead)
    if token is not None and token.kind != TOK.S_SPLIT:
        if not in_sentence and token.kind not in TOK.END:
            # Starting something here
            yield tok_begin_sentence
            in_sentence = True
        yield token
        if in_sentence and token.kind in {TOK.S_END, TOK.P_END}:
            in_sentence = False

    # Done with the input stream
    # If still inside a sentence, finish it
    if in_sentence:
        yield tok_end_sentence


def match_stem_list(token, stems):
    """ Find the stem of a word token in given dict, or return None if not found """
    if token.kind != TOK.WORD:
        return None
    return stems.get(token.txt.lower(), None)


def month_for_token(token, after_ordinal=False):
    """ Return a number, 1..12, corresponding to a month name,
        or None if the token does not contain a month name """
    if not after_ordinal and token.txt in MONTH_BLACKLIST:
        # Special case for 'Ágúst', which we do not recognize
        # as a month name unless it follows an ordinal number
        return None
    return match_stem_list(token, MONTHS)

  
def parse_phrases_1(token_stream):
    """ Handle dates and times """

    token = None
    try:

        # Maintain a one-token lookahead
        token = next(token_stream)
        while True:

            next_token = next(token_stream)
            # Coalesce abbreviations and trailing period
            if token.kind == TOK.WORD and next_token.txt == ".":
                abbrev = token.txt + next_token.txt
                if abbrev in Abbreviations.FINISHERS:
                    token = TOK.Word(abbrev, token.val)
                    next_token = next(token_stream)

            # Coalesce [year|number] + ['e.Kr.'|'f.Kr.'] into year
            if token.kind == TOK.YEAR or token.kind == TOK.NUMBER:
                val = token.val if token.kind == TOK.YEAR else token.val[0]
                nval = None
                if next_token.txt in BCE:  # f.Kr.
                    # Yes, we set year X BCE as year -X ;-)
                    nval = -val
                elif next_token.txt in CE:  # e.Kr.
                    nval = val
                if nval is not None:
                    token = TOK.Year(token.txt + " " + next_token.txt, nval)
                    next_token = next(token_stream)
                    if next_token.txt == ".":
                        token = TOK.Year(token.txt + next_token.txt, nval)
                        next_token = next(token_stream)
            # TODO: "5 mars" greinist sem dagsetning, vantar punktinn.
            # Check for [number | ordinal] [month name]
            if (
                token.kind == TOK.ORDINAL or token.kind == TOK.NUMBER
            ) and next_token.kind == TOK.WORD:

                month = month_for_token(next_token, True)
                if month is not None:
                    token = TOK.Date(
                        token.txt + " " + next_token.txt,
                        y=0,
                        m=month,
                        d=token.val if token.kind == TOK.ORDINAL else token.val[0],
                    )
                    # Eat the month name token
                    next_token = next(token_stream)

            # Check for [date] [year]
            if token.kind == TOK.DATE and next_token.kind == TOK.YEAR:

                if not token.val[0]:
                    # No year yet: add it
                    token = TOK.Date(
                        token.txt + " " + next_token.txt,
                        y=next_token.val,
                        m=token.val[1],
                        d=token.val[2],
                    )
                    # Eat the year token
                    next_token = next(token_stream)

            # Check for [date] [time]
            if token.kind == TOK.DATE and next_token.kind == TOK.TIME:
                # Create a time stamp
                y, mo, d = token.val
                h, m, s = next_token.val
                token = TOK.Timestamp(
                    token.txt + " " + next_token.txt, y=y, mo=mo, d=d, h=h, m=m, s=s
                )
                # Eat the time token
                next_token = next(token_stream)

            if (
                token.kind == TOK.NUMBER
                and next_token.kind == TOK.TELNO
                and token.txt in COUNTRY_CODES
            ):
                # Check for country code in front of telephone number
                token = TOK.Telno(
                    token.txt + " " + next_token.txt,
                    next_token.val[0],
                    cc=token.txt
                )
                next_token = next(token_stream)

            # Yield the current token and advance to the lookahead
            yield token
            token = next_token

    except StopIteration:
        pass

    # Final token (previous lookahead)
    if token:
        yield token


def parse_date_and_time(token_stream):
    """ Handle dates and times, absolute and relative. """

    token = None
    try:

        # Maintain a one-token lookahead
        token = next(token_stream)

        while True:

            next_token = next(token_stream)

            # TODO: "5 mars" endar sem dagsetning. Þarf að geta merkt.
            # DATEABS and DATEREL made
            # Check for [number | ordinal] [month name]
            if (
                token.kind == TOK.ORDINAL
                or token.kind == TOK.NUMBER
                # or (token.txt and token.txt.lower() in DAYS_OF_MONTH)
            ) and next_token.kind == TOK.WORD:
                month = month_for_token(next_token, True)
                if month is not None:
                    token = TOK.Date(
                        token.txt + " " + next_token.txt,
                        y=0,
                        m=month,
                        d=(
                            token.val
                            if token.kind == TOK.ORDINAL
                            else token.val[0]
                            # if token.kind == TOK.NUMBER
                            # else DAYS_OF_MONTH[token.txt.lower()]
                        ),
                    )
                    # Eat the month name token
                    next_token = next(token_stream)

            # Check for [DATE] [year]
            if token.kind == TOK.DATE and (
                next_token.kind == TOK.NUMBER or next_token.kind == TOK.YEAR
            ):
                if not token.val[0]:
                    # No year yet: add it
                    year = (
                        next_token.val
                        if next_token.kind == TOK.YEAR
                        else next_token.val[0]
                        if 1776 <= next_token.val[0] <= 2100
                        else 0
                    )
                    if year != 0:
                        token = TOK.Date(
                            token.txt + " " + next_token.txt,
                            y=year,
                            m=token.val[1],
                            d=token.val[2],
                        )
                        # Eat the year token
                        next_token = next(token_stream)
            
            # Check for [month name] [year|YEAR]
            if token.kind == TOK.WORD and (
                next_token.kind == TOK.NUMBER or next_token.kind == TOK.YEAR
            ):
                month = month_for_token(token)
                if month is not None:
                    year = (
                        next_token.val
                        if next_token.kind == TOK.YEAR
                        else next_token.val[0]
                        if 1776 <= next_token.val[0] <= 2100
                        else 0
                    )
                    if year != 0:
                        token = TOK.Date(
                            token.txt + " " + next_token.txt, y=year, m=month, d=0
                        )
                        # Eat the year token
                        next_token = next(token_stream)

            # Check for a single month, change to DATEREL
            if token.kind == TOK.WORD:
                month = month_for_token(token)
                # Don't automatically interpret "mar", etc. as month names,
                # since they are ambiguous
                if month is not None and token.txt not in AMBIGUOUS_MONTH_NAMES:
                    token = TOK.Daterel(token.txt, y=0, m=month, d=0)

            # Split DATE into DATEABS and DATEREL
            if token.kind == TOK.DATE:
                if token.val[0] and token.val[1] and token.val[2]:
                    token = TOK.Dateabs(
                        token.txt, y=token.val[0], m=token.val[1], d=token.val[2]
                    )
                else:
                    token = TOK.Daterel(
                        token.txt, y=token.val[0], m=token.val[1], d=token.val[2]
                    )

            # Split TIMESTAMP into TIMESTAMPABS and TIMESTAMPREL
            if token.kind == TOK.TIMESTAMP:
                if all(x != 0 for x in token.val[0:3]):
                    # Year, month and day all non-zero (h, m, s can be zero)
                    token = TOK.Timestampabs(token.txt, *token.val)
                else:
                    token = TOK.Timestamprel(token.txt, *token.val)

            # Swallow "e.Kr." and "f.Kr." postfixes
            if token.kind == TOK.DATEABS:
                if next_token.kind == TOK.WORD and next_token.txt in CE_BCE:
                    y = token.val[0]
                    if next_token.txt in BCE:
                        # Change year to negative number
                        y = -y
                    token = TOK.Dateabs(
                        token.txt + " " + next_token.txt,
                        y=y,
                        m=token.val[1],
                        d=token.val[2],
                    )
                    # Swallow the postfix
                    next_token = next(token_stream)

            # Check for [date] [time] (absolute)
            if token.kind == TOK.DATEABS:
                if next_token.kind == TOK.TIME:
                    # Create an absolute time stamp
                    y, mo, d = token.val
                    h, m, s = next_token.val
                    token = TOK.Timestampabs(
                        token.txt + " " + next_token.txt,
                        y=y, mo=mo, d=d, h=h, m=m, s=s
                    )
                    # Eat the time token
                    next_token = next(token_stream)

            # Check for [date] [time] (relative)
            if token.kind == TOK.DATEREL:
                if next_token.kind == TOK.TIME:
                    # Create a time stamp
                    y, mo, d = token.val
                    h, m, s = next_token.val
                    token = TOK.Timestamprel(
                        token.txt + " " + next_token.txt,
                        y=y, mo=mo, d=d, h=h, m=m, s=s
                    )
                    # Eat the time token
                    next_token = next(token_stream)

            # Yield the current token and advance to the lookahead
            yield token
            token = next_token

    except StopIteration:
        pass

    # Final token (previous lookahead)
    if token:
        yield token


def parse_phrases_2(token_stream, coalesce_percent=False):
    """ Handle numbers, amounts and composite words. """

    token = None
    try:

        # Maintain a one-token lookahead
        token = next(token_stream)

        while True:

            next_token = next(token_stream)

            # Logic for numbers and fractions that are partially or entirely
            # written out in words

            def number(tok):
                """ If the token denotes a number, return that number - or None """
                if tok.txt.lower() == "áttu":
                    # Do not accept 'áttu' (stem='átta', no kvk) as a number
                    return None
                return match_stem_list(tok, MULTIPLIERS)

            # Check whether we have an initial number word
            multiplier = number(token) if token.kind == TOK.WORD else None

            # Check for [number] 'hundred|thousand|million|billion'
            while (
                token.kind == TOK.NUMBER or multiplier is not None
            ) and next_token.kind == TOK.WORD:

                multiplier_next = number(next_token)

                def convert_to_num(token):
                    if multiplier is not None:
                        token = TOK.Number(token.txt, multiplier)
                    return token

                if multiplier_next is not None:
                    # Retain the case of the last multiplier
                    token = convert_to_num(token)
                    token = TOK.Number(
                        token.txt + " " + next_token.txt, token.val[0] * multiplier_next
                    )
                    # Eat the multiplier token
                    next_token = next(token_stream)
                elif next_token.txt in AMOUNT_ABBREV:
                    # Abbreviations for ISK amounts
                    # For abbreviations, we do not know the case,
                    # but we try to retain the previous case information if any
                    token = convert_to_num(token)
                    token = TOK.Amount(
                        token.txt + " " + next_token.txt,
                        "ISK",
                        token.val[0] * AMOUNT_ABBREV[next_token.txt],
                    )
                    next_token = next(token_stream)
                elif next_token.txt in CURRENCY_ABBREV:
                    # A number followed by an ISO currency abbreviation
                    token = convert_to_num(token)
                    token = TOK.Amount(
                        token.txt + " " + next_token.txt, next_token.txt, token.val[0]
                    )
                    next_token = next(token_stream)
                else:
                    # Check for [number] 'prósent/prósentustig/hundraðshluta'
                    if coalesce_percent:
                        percentage = match_stem_list(next_token, PERCENTAGES)
                    else:
                        percentage = None
                    if percentage is None:
                        break
                    # We have '17 prósent': coalesce into a single token
                    token = convert_to_num(token)
                    token = TOK.Percent(
                        token.txt + " " + next_token.txt, token.val[0]
                    )
                    # Eat the percent word token
                    next_token = next(token_stream)

                multiplier = None

            # Check for [currency] [number] (e.g. kr. 9.900 or USD 50)
            if next_token.kind == TOK.NUMBER and (
                token.txt in ISK_AMOUNT_PRECEDING or token.txt in CURRENCY_ABBREV
            ):
                curr = "ISK" if token.txt in ISK_AMOUNT_PRECEDING else token.txt
                token = TOK.Amount(
                    token.txt + " " + next_token.txt, curr, next_token.val[0]
                )
                next_token = next(token_stream)

            # Check for composites:
            # 'stjórnskipunar- og eftirlitsnefnd'
            # 'dómsmála-, viðskipta- og iðnaðarráðherra'
            tq = []
            while (
                token.kind == TOK.WORD
                and next_token.kind == TOK.PUNCTUATION
                and next_token.val[1] == COMPOSITE_HYPHEN 
            ):
                # Accumulate the prefix in tq
                tq.append(token)
                tq.append(TOK.Punctuation(next_token.txt, normalized=HYPHEN))
                # Check for optional comma after the prefix
                comma_token = next(token_stream)
                if comma_token.kind == TOK.PUNCTUATION and comma_token.val[1] == ",":
                    # A comma is present: append it to the queue
                    # and skip to the next token
                    tq.append(comma_token)
                    comma_token = next(token_stream)
                # Reset our two lookahead tokens
                token = comma_token
                next_token = next(token_stream)

            if tq:
                # We have accumulated one or more prefixes
                # ('dómsmála-, viðskipta-')
                if token.kind == TOK.WORD and token.txt in ("og", "eða"):
                    # We have 'viðskipta- og'
                    if next_token.kind != TOK.WORD:
                        # Incorrect: yield the accumulated token
                        # queue and keep the current token and the
                        # next_token lookahead unchanged
                        for t in tq:
                            yield t
                    else:
                        # We have 'viðskipta- og iðnaðarráðherra'
                        # Return a single token with the meanings of
                        # the last word, but an amalgamated token text.
                        # Note: there is no meaning check for the first
                        # part of the composition, so it can be an unknown word.
                        txt = " ".join(t.txt for t in tq + [token, next_token])
                        txt = txt.replace(" -", "-").replace(" ,", ",")
                        token = TOK.Word(txt)
                        next_token = next(token_stream)
                else:
                    # Incorrect prediction: make amends and continue
                    for t in tq:
                        yield t

            # Yield the current token and advance to the lookahead
            yield token
            token = next_token

    except StopIteration:
        pass

    # Final token (previous lookahead)
    if token:
        yield token


def tokenize(text_or_gen, **options):
    """ Tokenize text in several phases, returning a generator
        (iterable sequence) of tokens that processes tokens on-demand. """

    # Thank you Python for enabling this programming pattern ;-)

    # Make sure that the abbreviation config file has been read
    Abbreviations.initialize()
    with_annotation = options.pop("with_annotation", True)
    coalesce_percent = options.pop("coalesce_percent", False)

    token_stream = parse_tokens(text_or_gen, **options)
    token_stream = parse_particles(token_stream, **options)
    token_stream = parse_sentences(token_stream)
    token_stream = parse_phrases_1(token_stream)
    token_stream = parse_date_and_time(token_stream)

    # Skip the parse_phrases_2 pass if the with_annotation option is False
    if with_annotation:
        token_stream = parse_phrases_2(token_stream, coalesce_percent=coalesce_percent)

    return (t for t in token_stream if t.kind != TOK.X_END)


def tokenize_without_annotation(text_or_gen, **options):
    """ Tokenize without the last pass which can be done more thoroughly if BÍN
        annotation is available, for instance in ReynirPackage. """
    return tokenize(text_or_gen, with_annotation=False, **options)


def split_into_sentences(text_or_gen, **options):
    """ Shallow tokenization of the input text, which can be either
        a text string or a generator of lines of text (such as a file).
        This function returns a generator of strings, where each string
        is a sentence, and tokens are separated by spaces. """
    if options.pop("normalize", False):
        to_text = normalized_text
    else:
        to_text = lambda t: t.txt
    curr_sent = []
    for t in tokenize_without_annotation(text_or_gen, **options):
        if t.kind in TOK.END:
            # End of sentence/paragraph
            if curr_sent:
                yield " ".join(curr_sent)
                curr_sent = []
        else:
            txt = to_text(t)
            if txt:
                curr_sent.append(txt)
    if curr_sent:
        yield " ".join(curr_sent)


def mark_paragraphs(txt):
    """ Insert paragraph markers into plaintext, by newlines """
    if not txt:
        return "[[ ]]"
    return "[[ " + " ]] [[ ".join(txt.split("\n")) + " ]]"


def paragraphs(tokens):
    """ Generator yielding paragraphs from token iterable. Each paragraph is a list
        of sentence tuples. Sentence tuples consist of the index of the first token
        of the sentence (the TOK.S_BEGIN token) and a list of the tokens within the
        sentence, not including the starting TOK.S_BEGIN or the terminating TOK.S_END
        tokens. """

    if not tokens:
        return

    def valid_sent(sent):
        """ Return True if the token list in sent is a proper
            sentence that we want to process further """
        if not sent:
            return False
        # A sentence with only punctuation is not valid
        return any(t[0] != TOK.PUNCTUATION for t in sent)

    sent = []  # Current sentence
    sent_begin = 0
    current_p = []  # Current paragraph

    for ix, t in enumerate(tokens):
        t0 = t[0]
        if t0 == TOK.S_BEGIN:
            sent = []
            sent_begin = ix
        elif t0 == TOK.S_END:
            if valid_sent(sent):
                # Do not include or count zero-length sentences
                current_p.append((sent_begin, sent))
            sent = []
        elif t0 == TOK.P_BEGIN or t0 == TOK.P_END:
            # New paragraph marker: Start a new paragraph if we didn't have one before
            # or if we already had one with some content
            if valid_sent(sent):
                current_p.append((sent_begin, sent))
            sent = []
            if current_p:
                yield current_p
                current_p = []
        else:
            sent.append(t)

    if valid_sent(sent):
        current_p.append((sent_begin, sent))
    if current_p:
        yield current_p


RE_SPLIT_STR = (
    # The following regex catches Icelandic numbers with dots and a comma
    r"([\+\-\$€]?\d{1,3}(?:\.\d\d\d)+\,\d+)"  # +123.456,789
    # The following regex catches English numbers with commas and a dot
    r"|([\+\-\$€]?\d{1,3}(?:\,\d\d\d)+\.\d+)"  # +123,456.789
    # The following regex catches Icelandic numbers with a comma only
    r"|([\+\-\$€]?\d+\,\d+(?!\.\d))"  # -1234,56
    # The following regex catches English numbers with a dot only
    r"|([\+\-\$€]?\d+\.\d+(?!\,\d))"  # -1234.56
    # Finally, space and punctuation
    r"|([~\s"
    + "".join("\\" + c for c in PUNCTUATION)
    + r"])"
)
RE_SPLIT = re.compile(RE_SPLIT_STR)


def correct_spaces(s):
    """ Utility function to split and re-compose a string
        with correct spacing between tokens.
        NOTE that this function uses a quick-and-dirty approach
        which may not handle all edge cases! """
    r = []
    last = TP_NONE
    double_quote_count = 0
    for w in RE_SPLIT.split(s):
        if w is None:
            continue
        w = w.strip()
        if not w:
            continue
        if len(w) > 1:
            this = TP_WORD
        elif w == '"':
            # For English-type double quotes, we glue them alternatively
            # to the right and to the left token
            this = (TP_LEFT, TP_RIGHT)[double_quote_count % 2]
            double_quote_count += 1
        elif w in LEFT_PUNCTUATION:
            this = TP_LEFT
        elif w in RIGHT_PUNCTUATION:
            this = TP_RIGHT
        elif w in NONE_PUNCTUATION:
            this = TP_NONE
        elif w in CENTER_PUNCTUATION:
            this = TP_CENTER
        else:
            this = TP_WORD
        if (
            (w == "og" or w == "eða") and
            len(r) >= 2 and r[-1] == "-" and
            r[-2].lstrip().isalpha()
        ):
            # Special case for compounds such as "fjármála- og efnahagsráðuneytið"
            # and "Iðnaðar-, ferðamála- og atvinnuráðuneytið":
            # detach the hyphen from "og"/"eða"
            r.append(" " + w)
        elif (
            this == TP_WORD and len(r) >= 2 and
            r[-1] == "-" and w.isalpha() and
            (r[-2] == "," or r[-2].lstrip() in ("og", "eða"))
        ):
            # Special case for compounds such as
            # "bensínstöðvar, -dælur og -tankar"
            r[-1] = " -"
            r.append(w)
        elif TP_SPACE[last - 1][this - 1] and r:
            r.append(" " + w)
        else:
            r.append(w)
        last = this
    return "".join(r)


def detokenize(tokens, normalize=False):
    """ Utility function to convert an iterable of tokens back
        to a correctly spaced string. If normalize is True,
        punctuation is normalized before assembling the string. """
    to_text = normalized_text if normalize else lambda t: t.txt
    r = []
    last = TP_NONE
    double_quote_count = 0
    for t in tokens:
        w = to_text(t)
        if not w:
            continue
        this = TP_WORD
        if t.kind == TOK.PUNCTUATION:
            if len(w) > 1:
                pass
            elif w == '"':
                # For English-type double quotes, we glue them alternatively
                # to the right and to the left token
                this = (TP_LEFT, TP_RIGHT)[double_quote_count % 2]
                double_quote_count += 1
            elif w in LEFT_PUNCTUATION:
                this = TP_LEFT
            elif w in RIGHT_PUNCTUATION:
                this = TP_RIGHT
            elif w in NONE_PUNCTUATION:
                this = TP_NONE
            elif w in CENTER_PUNCTUATION:
                this = TP_CENTER
        if TP_SPACE[last - 1][this - 1] and r:
            r.append(" " + w)
        else:
            r.append(w)
        last = this
    return "".join(r)
