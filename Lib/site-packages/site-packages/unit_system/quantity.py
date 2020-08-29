"""Definition of Quantity as a subclass of Unyt's unyt_array"""
import numpy as np
from unyt import unyt_array, unyt_quantity, Unit

QUANTITY_FUNCTIONS = {}


class Quantity(unyt_array):
    """A physical quantity data type in the SI system

    Attributes:
        value (float or array-like): numerical value(s) of the quantity
        unit (str): original SI unit expression
        to_unit (str): coerce to given SI unit expression. Defaults to 'auto'

    Example:
        >>> from unit_system import Quantity
        >>> m = Quantity(1, "m")
        >>> length = 1*m
        >>> length
        1.0 m
        >>> 2*length
        2.0 m
        >>> lengths = [1, 2, 3]*m
        >>> lengths
        [1. 2. 3.] m
        >>> lengths.sum()
        6.0 m
        >>> V = Quantity(1, "V")
        >>> kV = 1e3*V
        >>> potential = 10*kV
        >>> potential
        10000.0 V
        >>> potential.to("kV")
        10.0 kV
    """

    # pylint: disable=arguments-differ
    # pylint: disable=unused-argument
    # pylint: disable=super-init-not-called
    def __new__(cls, value, unit, to_unit="auto", **kwargs):
        if isinstance(unit, str):
            unit = unit.replace("°", "deg")
        obj = super().__new__(Quantity, value, unit, **kwargs)
        obj.to_unit = to_unit
        return obj

    def __init__(self, value, unit, to_unit="auto", **kwargs):
        self.to(to_unit)

    def __getitem__(self, item):
        try:
            ret = super().__getitem__(item)
        except IndexError as err:
            if item == 0:
                ret = self
            else:
                raise IndexError from err
        return ret

    def __array_ufunc__(self, ufunc, method, *inputs, **kwargs):
        result = super().__array_ufunc__(ufunc, method, *inputs, **kwargs)
        if isinstance(result, unyt_quantity):
            result = Quantity(result, result.units)
        elif isinstance(result, np.ndarray):
            return result
        result.convert_to_base()
        return result

    def to(self, unit):
        if isinstance(unit, Unit):
            return super().to(unit)
        self.to_unit = unit
        if unit == "auto":
            self.convert_to_base()
        else:
            unit = unit.replace("°", "deg")
            self.convert_to_units(unit)
        return self

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        if self.units.is_dimensionless:
            return str(self.v)
        q_str = super().__str__()
        return q_str.replace("deg", "°")

    def threshold(self, value, start=0):
        """Find fractional index of value in a 1D Quantity array

        Args:
            value (Quantity)
            start (int)

        Returns:
            (float): fractional index where value is between two consequtive elements
                or None if not found or if a scalar or if not 1D array.
        """
        if self.ndim == 0 or self.ndim > 1:
            return None
        indices = np.nonzero(value >= self[start:])[0]
        try:
            lower_index = start + indices[-1]
        except IndexError:
            return None
        lower_value = self[lower_index]
        try:
            upper_value = self[start + lower_index + 1]
        except IndexError:
            return None
        fractional = (value - lower_value) / (upper_value - lower_value)
        return float(lower_index + fractional)

    def interpolate(self, index):
        """Compute value at fractional index of 1D Quantity array

        Args:
            index (float): fractional index

        Returns:
            (Quantity): linearly interpolated value between two consequtive elements
                or None if not found or if a scalar or if not a 1D array
        """
        if self.ndim == 0 or self.ndim > 1:
            return None
        lower_index = int(np.floor(index))
        lower_value = self[lower_index]
        upper_index = int(np.ceil(index))
        upper_value = self[upper_index]
        fractional = (upper_value - lower_value) * (index - lower_index)
        return lower_value + fractional

    def __array_function__(self, func, types, args, kwargs):
        if func not in QUANTITY_FUNCTIONS:
            return NotImplemented
        if not all(issubclass(t, Quantity) for t in types):
            return NotImplemented
        return QUANTITY_FUNCTIONS[func](*args, **kwargs)


def implements(numpy_function):
    """Register an __array_function__ implementation"""

    def decorator(func):
        QUANTITY_FUNCTIONS[numpy_function] = func
        return func

    return decorator


@implements(np.concatenate)
def concatenate(arrays):
    """Join a sequence of 1-D Quantity arrays

    Args:
        arrays (Quantity): sequence of Quantity arrays
    """
    arrays[0].to("auto")
    u0 = arrays[0].units
    unitless_arrays = [arrays[0].v]
    for array in arrays[1:]:
        array.to("auto")
        ux = array.units
        # pylint: disable=protected-access
        if not (u0 / ux).is_dimensionless:
            raise ValueError("incompatible units")
        unitless_arrays.append(array.value)
    cat_array = np.concatenate(unitless_arrays)
    return Quantity(cat_array, u0)
