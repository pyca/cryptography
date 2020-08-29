#!/usr/bin/env python
# coding=utf-8

"""Converter object to handle string input."""

from decimal import Decimal as D

from unit_converter.parser import QuantityParser, UnitParser


def convert(quantity: str, desired_unit: str) -> D:
    """

    :param quantity:
    :param desired_unit:
    :return:

    Examples :
    ----------

    >>> from unit_converter import convert
    >>> convert('2.78 daN*mm^2', 'mN*µm^2')
    Decimal('2.78E+10')
    """
    quantity = QuantityParser().parse(quantity)
    desired_unit = UnitParser().parse(desired_unit)
    return quantity.convert(desired_unit).value


def converts(quantity: str, desired_unit: str) -> str:
    """

    :param quantity:
    :param desired_unit:
    :return:

    Examples :
    ----------

    >>> from unit_converter import convert
    >>> convert('2.78 daN*mm^2', 'mN*µm^2')
    Decimal('2.78E+10')
    """
    return str(convert(quantity, desired_unit))


if __name__ == "__main__":
    import doctest
    doctest.testmod()
