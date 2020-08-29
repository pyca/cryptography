# -*- coding: utf-8 -*-

import warnings

import numpy as np


class Unit:
    """The Unit class that is defined by a set of (base unit, power).

    It is defined by 0, 1 or many base units (str) raised to a power.  
    For instance, an acceleration can be represented by the following dict {'m': 1, 's': -2} (m·s⁻²).  

    These operators are implemented: ``==``, ``*``, ``/``, ``//``, ``__pow__`` as well as their __r{op}__ (except for the ``__pow__``).  
    However no in-place operators (__i{op}__) has been implemented yet.


    Parameters
    ----------
    u
        * If u is a string, create a Unit with a single base unit ``u`` raised to the power ``n`` (default to 1).
        * If u is a Unit, create a copy of it.
        * If u is a dict where each key is a string an each value a scalar (np.isscalar), create an Unit based on these base unit and raised to the power associated.

    n : :obj:`int`, optional
        If ``u`` is a `str`, n is the power to which u is raised to create the new Unit. Default to 1.


    Example
    -------
    >>> Unit('m') == Unit('m', 1) and Unit('m') == Unit({'m': 1})
    True
    >>> Unit('m') * Unit('sec', -2) == Unit({'m': 1, 'sec': -2})
    True
    >>> Unit('€') ** 2
    €²
    >>> Unit('€') + Unit('$')
    TypeError: unsupported operand type(s) for +: 'Unit' and 'Unit'

    """
    def __init__(self, u={}, n=1):
        if isinstance(u, Unit):
            self.u = u.u
        elif type(u) is str:
            self.u = {
                u: n
            }
        elif type(u) is dict:
            if all(type(key) is str and np.isscalar(value) for (key, value) in u.items()): # dict is well formed
                self.u = u
            else:
                warnings.warn('The dict passed to the Unit constructor is not valid. Returning empty Unit.')
                self.u = {}
        else:
            self.u = {}
    
    def __repr__(self):
        dict_power = {
            '-': '⁻',
            '0': '⁰',
            '1': '¹',
            '2': '²',
            '3': '³',
            '4': '⁴',
            '5': '⁵',
            '6': '⁶',
            '7': '⁷',
            '8': '⁸',
            '9': '⁹',
        }

        units_str = []       
        for (unit, n) in self.u.items():
            tmp_rep = u''
            if n == 0: # don't print anything
                continue
        
            tmp_rep += unit
            if n != 1: # don't print any power if n=1
                if n == int(n): # power is an integer
                    for c in str(int(n)):
                        tmp_rep += dict_power[c]
                else: # power is a float
                    tmp_rep += f'^{n}'
            units_str.append(tmp_rep)
        
        units_str.sort()
        if len(units_str) == 0:
            return u'∅'
        return u'·'.join(units_str)

    def __str__(self):
        return self.__repr__()


    def __eq__(self, other):
        if not isinstance(other, Unit):
            return False

        for (unit, n) in self.u.items():
            if other.u.get(unit, 0) != n:
                return False
        for (unit, n) in other.u.items():
            if self.u.get(unit, 0) != n:
                return False
        
        return True

    def _make_op(self, other, func):
        other = Unit(other)

        result = {}
        for (unit, n) in self.u.items():
            result[unit] = n # just a copy of self.u
        for (unit, n) in other.u.items():
            value = result.get(unit, 0) # value is combined if already present, else it's 0
            value = func(value, n)
            result[unit] = value
        return Unit(result)

    def __mul__(self, other):
        return self._make_op(other, lambda i, o: i + o)

    def __rmul__(self, other):
        return self * other # simply call __mul__

    def __truediv__(self, other):
        return self._make_op(other, lambda i, o: i - o)
    
    def __rtruediv__(self, other): # case other / Unit
        other = Unit(other)

        result = {}
        for (unit, n) in other.u.items():
            result[unit] = n # just a copy of other.u
        for (unit, n) in self.u.items():
            value = result.get(unit, 0)
            value -= n
            result[unit] = value
        return Unit(result)

    def __floordiv__(self, other):
        return self / other # simply call __truediv__
    
    def __rfloordiv__(self, other):
        return other / self # simply call __rtruediv__

    def __pow__(self, other, mod=None):
        res = {}
        if np.isscalar(other):
            for (unit, n) in self.u.items():
                res[unit] = n * other
        return Unit(res)



class ArrayUnit(np.ndarray):
    """The class defining a multi dimensionnal array combined with a ``Unit``.  

    These operators are implemented: ``==``, ``+``, ``-``, ``*``, ``/``, ``//``, ``%``, ``__pow__`` as well as their __r{op}__ (except for the ``__pow__``) and their __i{op}__ variants.  
    The level of strictness can be set in order to add, substract or use a modulo between two ArrayUnit with different ``Unit``.  

    The following rules applied (where {op} is one of the following: [``+``, ``-``, ``*``, ``/``, ``//``, ``%``]):  

    * ArrayUnit {op} Object returns an ArrayUnit with the same unit as the ArrayUnit
    * Object {op} ArrayUnit returns an ArrayUnit with the same unit as the ArrayUnit
    * ArrayUnit {op} ArrayUnit returns an ArrayUnit combining the Unit of the 2 ArrayUnit or an Error
    * An Error might be raised only when two ArrayUnit are conflicting and that ArrayUnit.is_strict is set to True. Otherwise, it would print a warning.
    * An ArrayUnit is equal to a numpy.ndarray if and only if their underlying arrays are equal (np.array_equal) and the Unit of the ArrayUnit is empty.


    Parameters
    ----------
    input_array : numpy.ndarray
        The array on which the ArrayUnit will be based on. No copy is made, i.e. the original array and ``self`` will share the same underlying memory.
    unit : Unit
        The `Unit` in which the values of the input_array are expressed.


    Attributes
    ----------
    is_set: bool
        Set the strictness to either True or False.  
        If it is set True, a `ValueError` might be raised while adding, substracting or modulo two `ArrayUnit` with different `Unit`.  
        If it is set to True, a warning is triggered when making an impossible operation.  


    Examples
    --------
    >>> ArrayUnit.is_strict = True
    >>> m = Unit('m')
    >>> s = Unit('s', -2)
    >>> arr = np.linspace(1,10,10, dtype=float)
    >>> a = ArrayUnit(arr, m)
    >>> b = ArrayUnit(arr**2, s)
    >>> print(a, '\\n+\\n', 1, '\\n=\\n', a + 1)
    [ 1.  2.  3.  4.  5.  6.  7.  8.  9. 10.] m
    +
    1 
    =
    [ 2.  3.  4.  5.  6.  7.  8.  9. 10. 11.] m
    >>> print(a, '\\n-\\n', arr, '\\n=\\n', a - arr)
    [ 1.  2.  3.  4.  5.  6.  7.  8.  9. 10.] m
    -
    [ 1.  2.  3.  4.  5.  6.  7.  8.  9. 10.]
    =
    [0. 0. 0. 0. 0. 0. 0. 0. 0. 0.] m
    >>> print(a, '\\n*\\n', b, '\\n=\\n', a * b)
    [ 1.  2.  3.  4.  5.  6.  7.  8.  9. 10.] m
    *
    [  1.   4.   9.  16.  25.  36.  49.  64.  81. 100.] s⁻²
    =
    [   1.    8.   27.   64.  125.  216.  343.  512.  729. 1000.] m·s⁻²
    >>> print(b, '\\n//\\n', a, '\\n=\\n', b / a)
    [  1.   4.   9.  16.  25.  36.  49.  64.  81. 100.] s⁻²
    //
    [ 1.  2.  3.  4.  5.  6.  7.  8.  9. 10.] m
    =
    [ 1.  2.  3.  4.  5.  6.  7.  8.  9. 10.] m⁻¹·s⁻²


    """

    is_strict: bool = False

    # see https://docs.scipy.org/doc/numpy-1.13.0/user/basics.subclassing.html
    def __new__(cls, input_array, unit=None):
        # Input array is an already formed ndarray instance
        # We first cast to be our class type
        obj = np.asarray(input_array).view(cls)
        # add the new attribute to the created instance
        if unit is None:
            unit = Unit()
        obj.unit = unit
        # Finally, we must return the newly created object:
        return obj

    def __array_finalize__(self, obj):
        if obj is None:
            return
        self.unit = getattr(obj, 'unit', None)
    
    def __repr__(self):
        return super(ArrayUnit, self).__repr__() + ' ' + repr(self.unit)
 
    def __str__(self):
        return super(ArrayUnit, self).__str__() + ' ' + str(self.unit)

    def __eq__(self, other):
        if isinstance(other, ArrayUnit):
            return np.array_equal(self, other) and self.unit == other.unit
        if isinstance(other, np.ndarray): # construct an empty unit and call recursively
            return ArrayUnit(other, Unit()) == self
        return False
    
    def __ne__(self, other):
        if isinstance(other, ArrayUnit):
            return not self == other
        if isinstance(other, np.ndarray): # construct an empty unit and call recursively
            return ArrayUnit(other, Unit()) != self
        return True

    def _make_op(self, other, func_name, func, check=True):
        other_unit = Unit()
        if isinstance(other, ArrayUnit):
            other_unit = other.unit
            if other_unit != self.unit and check:
                if ArrayUnit.is_strict:
                    raise ValueError(f'Can not {func_name} two ArrayUnit with different units: {self.unit} {func_name} {other.unit}')
                else:
                    warnings.warn(f'Applying {func_name} to two ArrayUnit with different units: {self.unit} and {other.unit}. Returning {self.unit}')
        res = getattr(super(ArrayUnit, self), func_name)(other) # apply func_name the numpy way
        res.unit = func(self.unit, other_unit) # now perform operations on unit
        return res
    
    def __add__(self, other):
        return self._make_op(other, '__add__', lambda i, o: i) # when adding 2 things, no operation on their units

    def __radd__(self, other):
        return self._make_op(other, '__radd__', lambda i, o: i)
    
    def __iadd__(self, other):
        return self._make_op(other, '__iadd__', lambda i, o: i)

    def __sub__(self, other):
        return self._make_op(other, '__sub__', lambda i, o: i) # when adding 2 substracting, no operation on their units
    
    def __rsub__(self, other):
        return self._make_op(other, '__rsub__', lambda i, o: i)
    
    def __isub__(self, other):
        return self._make_op(other, '__isub__', lambda i, o: i)

    def __mul__(self, other):
        return self._make_op(other, '__mul__', lambda i, o: i * o, check=False) # self and other can have different units
    
    def __rmul__(self, other):
        return self._make_op(other, '__rmul__', lambda i, o: o * i, check=False) # self and other can have different units
    
    def __imul__(self, other):
        return self._make_op(other, '__imul__', lambda i, o: o * i, check=False) # self and other can have different units
    
    def __truediv__(self, other):
        return self._make_op(other, '__truediv__', lambda i, o: i / o, check=False) # self and other can have different units
    
    def __rtruediv__(self, other):
        return self._make_op(other, '__rtruediv__', lambda i, o: o / i, check=False) # self and other can have different units
    
    def __itruediv__(self, other):
        return self._make_op(other, '__itruediv__', lambda i, o: i / o, check=False) # self and other can have different units

    def __floordiv__(self, other):
        return self._make_op(other, '__floordiv__', lambda i, o: i // o, check=False) # self and other can have different units
    
    def __rfloordiv__(self, other):
        return self._make_op(other, '__rfloordiv__', lambda i, o: o // i, check=False) # self and other can have different units
    
    def __ifloordiv__(self, other):
        return self._make_op(other, '__ifloordiv__', lambda i, o: o // i, check=False) # self and other can have different units
    
    def __mod__(self, other):
        return self._make_op(other, '__mod__', lambda i, o: i, check=True)
    
    def __rmod__(self, other):
        return self._make_op(other, '__rmod__', lambda i, o: i, check=True)
    
    def __imod__(self, other):
        return self._make_op(other, '__imod__', lambda i, o: i, check=True)

    def __pow__(self, other, mod=None):
        res = self._make_op(other, '__pow__', lambda i, o: i, check=False)
        res.unit = self.unit ** other
        return res
    
    def __ipow__(self, other, mod=None):
        res = self._make_op(other, '__ipow__', lambda i, o: i, check=False)
        res.unit = self.unit ** other
        return res
