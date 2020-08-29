#!/usr/bin/env python
# coding=utf-8

from decimal import Decimal as D

from unit_converter.exceptions import UnConsistentUnitsError


class UnitPrefix(object):

    def __init__(self, symbol, name, factor):
        self.symbol = symbol
        self.name = name

        if isinstance(factor, str):
            self.factor = D(factor)
        elif isinstance(factor, D):
            self.factor = factor
        else:
            raise TypeError("factor need to be a 'string' or a"
                            " 'decimal.Decimal' class")

    def __repr__(self):
        return ("UnitPrefix(symbol='%s', name='%s', factor='%s')" %
                (self.symbol, self.name, self.factor))

    def is_same_factor(self, other_prefix):
        return self.factor == other_prefix.factor

    def __eq__(self, other_prefix):
        return (self.symbol == other_prefix.symbol and
                self.name == other_prefix.name and
                self.factor == other_prefix.factor)

    def __mul__(self, unit):
        if isinstance(unit, Unit):
            final_unit = Unit(symbol=self.symbol + unit.symbol,
                              name=self.name + unit.name,
                              L=unit.L,
                              M=unit.M,
                              T=unit.T,
                              I=unit.I,
                              THETA=unit.THETA,
                              N=unit.N,
                              J=unit.J,
                              coef=self.factor * unit.coef,
                              offset=unit.offset)
            return final_unit
        else:
            raise TypeError("unsupported operand type(s) for : '%s' and '%s'" %
                            (type(self), type(unit)))


class Unit(object):

    def __init__(self, symbol, name, plural_name=None,
                 L=0, M=0, T=0, I=0, THETA=0, N=0, J=0,
                 coef=D('1'), offset=D('0')):
        self.symbol = symbol
        self.name = name
        self.plural_name = plural_name or name
        self.coef = coef
        self.offset = offset

        # Dimensional quantities
        # -----------------------
        self.L = L              # Length
        self.M = M              # Mass
        self.T = T              # Time
        self.I = I              # Electric current
        self.THETA = THETA      # Thermodynamic temperature
        self.N = N              # Amount of substance
        self.J = J              # Light intensity

    def __repr__(self):
        # TODO: Add a better representation including coef and offset.
        # TODO: Hide plotting 0 dimension
        l_units_r = ("m^%s", "kg^%s", "s^%s", "A^%s", "K^%s", "mol^%s", "cd^%s")
        units = (self.L, self.M, self.T, self.I, self.THETA, self.N, self.J)

        unit_r = [r % units[idx] for idx, r in enumerate(l_units_r) if units[idx]]
        return '*'.join(unit_r)

    def is_same_dimension(self, other_unit):
        return (self.L == other_unit.L and
                self.M == other_unit.M and
                self.T == other_unit.T and
                self.I == other_unit.I and
                self.THETA == other_unit.THETA and
                self.N == other_unit.N and
                self.J == other_unit.J)

    def __eq__(self, other):
        return (self.is_same_dimension(other) and
                self.coef == other.coef and
                self.offset == other.offset)

    def __mul__(self, other):
        if isinstance(other, Unit):
            return self.__class__(symbol=self.symbol + '*' + other.symbol,
                                  name=self.name + '*' + other.name,
                                  L=self.L + other.L,
                                  M=self.M + other.M,
                                  T=self.T + other.T,
                                  I=self.I + other.I,
                                  THETA=self.THETA + other.THETA,
                                  N=self.N + other.N,
                                  J=self.J + other.J,
                                  coef=self.coef * other.coef,
                                  offset=self.offset + other.offset)
        elif type(other) in (int, float, D):
            return Quantity(value=other, unit=self)
        else:
            raise TypeError("unsupported operand type(s) for : '%s' and '%s'" %
                            (type(self), type(other)))

    def __pow__(self, power):
        if type(power) in (int, float, D):
            if self.offset:
                new_offset = self.offset**D(power)
            else:
                new_offset = self.offset
            final_unit = self.__class__(symbol=self.symbol + '^' + str(power),  # TODO: attention manque des parenthèses etc..
                                        name=self.name + '^' + str(power),
                                        L=self.L * power,
                                        M=self.M * power,
                                        T=self.T * power,
                                        I=self.I * power,
                                        THETA=self.THETA * power,
                                        N=self.N * power,
                                        J=self.J * power,
                                        coef=self.coef**D(power),
                                        offset=new_offset)
            return final_unit
        else:
            raise TypeError("unsupported operand type(s) for : '%s' and '%s'" %
                            (type(self), type(power)))

    def __truediv__(self, other):
        return self.__pow__(-1)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __rtruediv__(self, other):
        return self.__truediv__(other)


class Quantity(object):

    def __init__(self, value, unit):
        if type(value) in (int, float, D):
            self.value = value
        else:
            raise TypeError("value must be an int, float or decimal class")

        if isinstance(unit, Unit):
            self.unit = unit
        else:
            raise TypeError("unit must be an Unit class")

    def convert(self, desired_unit: Unit):
        # Check dimension from current and desired units
        if not desired_unit.is_same_dimension(self.unit):
            raise UnConsistentUnitsError(desired_unit.name, self.unit.name)

        default_value = self.unit.offset + self.value * self.unit.coef
        desired_value = (-desired_unit.offset + default_value) / desired_unit.coef
        return self.__class__(value=desired_value, unit=self.unit)

    def __repr__(self):
        return str(self.value) + ' ' + str(self.unit)

    def __add__(self, other):
        if isinstance(other, Quantity):
            if self.unit == other.unit:
                return self.__class__(self.value + other.value, self.unit)

    def __sub__(self, other):
        if isinstance(other, Quantity):
            if self.unit == other.unit:
                return self.__class__(self.value - other.value, self.unit)

    def __mul__(self, other):
        if isinstance(other, Quantity):
            if self.unit == other.unit:
                return self.__class__(self.value * other.value,
                                      self.unit * other.unit)

    def __truediv__(self, other):
        if isinstance(other, Quantity):
            if self.unit == other.unit:
                return self.__class__(self.value / other.value,
                                      self.unit / other.unit)

    def __radd__(self, other):
        return self.__add__(other)

    def __rsub__(self, other):
        return self.__sub__(other)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __rtruediv__(self, other):
        return self.__truediv__(other)
