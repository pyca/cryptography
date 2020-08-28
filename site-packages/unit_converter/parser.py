#!/usr/bin/env python
# coding=utf-8

import re
from decimal import Decimal as D
from functools import reduce

from unit_converter.data import PREFIXES, UNITS
from unit_converter.exceptions import UnitDoesntExistError
from unit_converter.units import Unit, Quantity


def parse(quantity: str) -> Quantity:
    return QuantityParser().parse(quantity)


class QuantityParser(object):

    quantity_re = re.compile("(?P<value>\d+[.,]?\d*)? *(?P<unit>.*)")

    def parse(self, quantity: str) -> Quantity:
        r = self.quantity_re.match(quantity)
        unit = UnitParser().parse(r.group("unit"))
        if r.group("value") is not None:
            if ',' in r.group("value"):
                value = D(r.group("value").replace(',', '.'))
            else:
                value = D(r.group("value"))
            return Quantity(value, unit)
        else:
            return unit


class UnitParser(object):
    unit_re = re.compile("(?P<unit>[a-zA-Z°Ωµ]+)\^?(?P<pow>[-+]?[0-9]*\.?[0-9]*)")

    def parse(self, unit: str) -> Unit:
        l_unit_s = self.unit_re.findall(unit)
        l_unit = [self._parse_unit(unit, power) for unit, power in l_unit_s]
        return reduce(lambda x, y: x * y, l_unit)

    def _parse_unit(self, unit: str, power: str) -> Unit:
        if power is '':
            return self._parse_simple_unit(unit)
        else:
            return self._parse_simple_unit(unit) ** float(power)

    @staticmethod
    def _parse_simple_unit(unit_s: str) -> Unit:
        """Parse a simple unit.

        In other word, parse an unit without a power value.
        """
        unit = None
        for prefix in PREFIXES.keys():
            if unit_s.startswith(prefix) and unit_s[len(prefix):] in UNITS.keys():
                unit = UNITS[unit_s[len(prefix):]]
                prefix = PREFIXES[prefix]
                break
        
        if unit is None:
            raise UnitDoesntExistError(unit_s)

        return prefix*unit
