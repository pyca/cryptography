# -*- encoding: utf-8 -*-
"""

    Abbreviations module for tokenization of Icelandic text

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

    
    This module reads the definition of abbreviations from the file
    Abbrev.conf, assumed to be located in the same directory (or installation
    resource library) as this Python source file.

"""

from __future__ import absolute_import
from __future__ import unicode_literals

import sys
if sys.version_info >= (3, 5):
    from typing import Set, List, Tuple, Dict, Any

from threading import Lock
from collections import defaultdict, OrderedDict


class ConfigError(Exception):

    pass


class OrderedSet:

    """ Shim class to provide an ordered set API on top
        of an OrderedDict. This is necessary to make abbreviation
        lookups predictable and repeatable, which they would not be
        if a standard Python set() was used. """

    def __init__(self):
        self._dict = OrderedDict()

    def add(self, item):
        """ Add an item at the end of the ordered set """
        if item not in self._dict:
            self._dict[item] = None

    def __contains__(self, item):
        return item in self._dict

    def __iter__(self):
        return self._dict.__iter__()


class Abbreviations:

    """ Wrapper around dictionary of abbreviations,
        initialized from the config file """

    # Dictionary of abbreviations and their meanings
    DICT = defaultdict(OrderedSet)  # type: Dict[str, Any]  # !!! TODO
    # Wrong versions of abbreviations
    WRONGDICT = defaultdict(OrderedSet)  # type: Dict[str, Any]  # !!! TODO
    # All abbreviation meanings
    MEANINGS = set()  # type: Set[str]
    # Single-word abbreviations, i.e. those with only one dot at the end
    SINGLES = set()  # type: Set[str]
    # Set of abbreviations without periods, e.g. "td", "osfrv"
    WRONGSINGLES = set()  # type: Set[str]
    # Potential sentence finishers, i.e. those with a dot at the end,
    # marked with an asterisk in the config file
    FINISHERS = set()  # type: Set[str]
    # Abbreviations that should not be seen as such at the end of sentences,
    # marked with an exclamation mark in the config file
    NOT_FINISHERS = set()  # type: Set[str]
    # Abbreviations that should not be seen as such at the end of sentences, but
    # are allowed in front of person names; marked with a hat ^ in the config file
    NAME_FINISHERS = set()  # type: Set[str]
    # Wrong versions of abbreviations with possible corrections
    # wrong version : [correction1, correction2, ...]
    WRONGDOTS = defaultdict(list)  # type: Dict[str, List[str]]

    # Ensure that only one thread initializes the abbreviations
    _lock = Lock()

    @staticmethod
    def add(abbrev, meaning, gender, fl=None):
        """ Add an abbreviation to the dictionary.
            Called from the config file handler. """
        # Check for sentence finishers
        finisher = False
        not_finisher = False
        name_finisher = False
        if abbrev.endswith("*"):
            # This abbreviation is explicitly allowed to finish a sentence
            finisher = True
            abbrev = abbrev[0:-1]
            if not abbrev.endswith("."):
                raise ConfigError(
                    "Only abbreviations ending with periods can be sentence finishers"
                )
        elif abbrev.endswith("!"):
            # A not-finisher cannot finish a sentence, because it is also a valid word
            # (Example: 'dags.', 'mín.', 'sek.')
            not_finisher = True
            abbrev = abbrev[0:-1]
            if not abbrev.endswith("."):
                raise ConfigError(
                    "Only abbreviations ending with periods "
                    "can be marked as not-finishers"
                )
        elif abbrev.endswith("^"):
            # This abbreviation can be followed by a name;
            # in other aspects it is like a not-finisher
            # (Example: 'próf.')
            name_finisher = True
            abbrev = abbrev[0:-1]
            if not abbrev.endswith("."):
                raise ConfigError(
                    "Only abbreviations ending with periods "
                    "can be marked as name finishers"
                )
        if abbrev.endswith("!") or abbrev.endswith("*") or abbrev.endswith("^"):
            raise ConfigError(
                "!, * and ^ modifiers are mutually exclusive on abbreviations"
            )
        # Append the abbreviation and its meaning in tuple form
        # Multiple meanings are supported for each abbreviation
        Abbreviations.DICT[abbrev].add(
            (
                meaning,
                0,
                gender,
                "skst" if fl is None else fl,
                abbrev,
                "-",
            )
        )
        Abbreviations.MEANINGS.add(meaning)
        # Adding wrong versions of abbreviations
        if abbrev[-1] == "." and "." not in abbrev[0:-1]:
            # Only one dot, at the end
            # Lookup is without the dot
            wabbrev = abbrev[0:-1]
            Abbreviations.SINGLES.add(wabbrev)
            if finisher:
                Abbreviations.FINISHERS.add(wabbrev)
            Abbreviations.WRONGDOTS[wabbrev].append(abbrev)
            if len(wabbrev) > 1:
                # We don't add single letters (such as Í and Á)
                # as abbreviations, even though they are listed as such
                # in the form 'Í.' and 'Á.' for use within person names
                Abbreviations.WRONGDICT[wabbrev].add(
                    (
                        meaning,
                        0,
                        gender,
                        "skst" if fl is None else fl,
                        wabbrev,
                        "-",
                    )
                )

        elif "." in abbrev:
            # Only multiple dots, checked single dots above
            # Want to see versions with each one deleted,
            # and one where all are deleted
            indices = [pos for pos, char in enumerate(abbrev) if char == "."]
            for i in indices:
                # Removing one dot at a time
                wabbrev = abbrev[:i] + abbrev[i+1:]
                #if finisher:
                #    Abbreviations.FINISHERS.add(wabbrev)
                Abbreviations.WRONGDOTS[wabbrev].append(abbrev)
                Abbreviations.WRONGDICT[wabbrev].add(
                    (
                        meaning,
                        0,
                        gender,
                        "skst" if fl is None else fl,
                        wabbrev,
                        "-",
                    )
                )
            if len(indices) > 2:
                # 3 or 4 dots currently in vocabulary
                # Not all cases with 4 dots are handled.
                i1 = indices[0]
                i2 = indices[1]
                i3 = indices[2]
                wabbrevs = []
                # 1 and 2 removed
                wabbrevs.append(abbrev[:i1]+abbrev[i1+1:i2]+abbrev[i2+1:])
                # 1 and 3 removed
                wabbrevs.append(abbrev[:i1]+abbrev[i1+1:i3]+abbrev[i3+1:])
                # 2 and 3 removed
                wabbrevs.append(abbrev[:i2]+abbrev[i2+1:i3]+abbrev[i3+1:])
                for wabbrev in wabbrevs:
                    #if finisher:
                    #    Abbreviations.FINISHERS.add(wabbrev)
                    Abbreviations.WRONGDOTS[wabbrev].append(abbrev)
                    Abbreviations.WRONGDICT[wabbrev].add(
                        (
                            meaning,
                            0,
                            gender,
                            "skst" if fl is None else fl,
                            wabbrev,
                            "-",
                        )
                    )
            # Removing all dots
            wabbrev = abbrev.replace(".", "")
            Abbreviations.WRONGSINGLES.add(wabbrev)
            #if finisher:
            #    Abbreviations.FINISHERS.add(wabbrev)
            Abbreviations.WRONGDOTS[wabbrev].append(abbrev)
            Abbreviations.WRONGDICT[wabbrev].add(
                (
                    meaning,
                    0,
                    gender,
                    "skst" if fl is None else fl,
                    wabbrev,
                    "-",
                )
            )
        if finisher:
            Abbreviations.FINISHERS.add(abbrev)
        if not_finisher or name_finisher:
            # Both name finishers and not-finishers are added to the NOT_FINISHERS set
            Abbreviations.NOT_FINISHERS.add(abbrev)
        if name_finisher:
            Abbreviations.NAME_FINISHERS.add(abbrev)

    @staticmethod
    def has_meaning(abbrev):
        return abbrev in Abbreviations.DICT or abbrev in Abbreviations.WRONGDICT

    @staticmethod
    def has_abbreviation(meaning):
        return meaning in Abbreviations.MEANINGS

    @staticmethod
    def get_meaning(abbrev):
        """ Lookup meaning(s) of abbreviation, if available. """
        m = Abbreviations.DICT.get(abbrev)
        if not m:
            m = Abbreviations.WRONGDICT.get(abbrev)
        return list(m) if m else None

    @staticmethod
    def _handle_abbreviations(s):
        """ Handle abbreviations in the settings section """
        # Format: abbrev[*] = "meaning" gender (kk|kvk|hk)
        # An asterisk after an abbreviation ending with a period
        # indicates that the abbreviation may finish a sentence
        a = s.split("=", 1)  # maxsplit=1
        if len(a) != 2:
            raise ConfigError(
                "Wrong format for abbreviation: should be abbreviation = meaning"
            )
        abbrev = a[0].strip()
        if not abbrev:
            raise ConfigError(
                "Missing abbreviation. Format should be abbreviation = meaning."
            )
        m = a[1].strip().split('"')
        par = ""
        if len(m) >= 3:
            # Something follows the last quote
            par = m[-1].strip()
        gender = "hk"  # Default gender is neutral
        fl = None  # Default word category is None
        if par:
            p = par.split()
            if len(p) >= 1:
                gender = p[0].strip()
            if len(p) >= 2:
                fl = p[1].strip()
        Abbreviations.add(abbrev, m[1], gender, fl)

    @staticmethod
    def initialize():
        """ Read the abbreviations config file """
        with Abbreviations._lock:
            if len(Abbreviations.DICT):
                # Already initialized
                return
            from pkg_resources import resource_stream
            with resource_stream(__name__, "Abbrev.conf") as config:
                for b in config:
                    # We get lines as binary strings
                    s = b.decode("utf-8")
                    # Ignore comments
                    ix = s.find("#")
                    if ix >= 0:
                        s = s[0:ix]
                    s = s.strip()
                    if not s:
                        # Blank line: ignore
                        continue
                    if s[0] == "[":
                        # Section header (we are expecting [abbreviations])
                        if s != "[abbreviations]":
                            raise ConfigError("Wrong section header")
                        continue
                    Abbreviations._handle_abbreviations(s)
