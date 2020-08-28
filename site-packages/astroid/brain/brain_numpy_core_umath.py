# Copyright (c) 2019 hippo91 <guillaume.peillex@gmail.com>

# Licensed under the LGPL: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html
# For details: https://github.com/PyCQA/astroid/blob/master/COPYING.LESSER


"""Astroid hooks for numpy.core.umath module."""

import astroid


def numpy_core_umath_transform():
    ufunc_optional_keyword_arguments = (
        """out=None, where=True, casting='same_kind', order='K', """
        """dtype=None, subok=True"""
    )
    return astroid.parse(
        """
    class FakeUfunc:
        def __init__(self):
            self.__doc__ = str()
            self.__name__ = str()
            self.nin = 0
            self.nout = 0
            self.nargs = 0
            self.ntypes = 0
            self.types = None
            self.identity = None
            self.signature = None

        @classmethod
        def reduce(cls, a, axis=None, dtype=None, out=None):
            return numpy.ndarray([0, 0])

        @classmethod
        def accumulate(cls, array, axis=None, dtype=None, out=None):
            return numpy.ndarray([0, 0])

        @classmethod
        def reduceat(cls, a, indices, axis=None, dtype=None, out=None):
            return numpy.ndarray([0, 0])

        @classmethod
        def outer(cls, A, B, **kwargs):
            return numpy.ndarray([0, 0])

        @classmethod
        def at(cls, a, indices, b=None):
            return numpy.ndarray([0, 0])

    class FakeUfuncOneArg(FakeUfunc):
        def __call__(self, x, {opt_args:s}):
            return numpy.ndarray([0, 0])

    class FakeUfuncOneArgBis(FakeUfunc):
        def __call__(self, x, {opt_args:s}):
            return numpy.ndarray([0, 0]), numpy.ndarray([0, 0])

    class FakeUfuncTwoArgs(FakeUfunc):
        def __call__(self, x1, x2, {opt_args:s}):
            return numpy.ndarray([0, 0])

    # Constants
    e = 2.718281828459045
    euler_gamma = 0.5772156649015329

    # One arg functions with optional kwargs
    arccos = FakeUfuncOneArg()
    arccosh = FakeUfuncOneArg()
    arcsin = FakeUfuncOneArg()
    arcsinh = FakeUfuncOneArg()
    arctan = FakeUfuncOneArg()
    arctanh = FakeUfuncOneArg()
    cbrt = FakeUfuncOneArg()
    conj = FakeUfuncOneArg()
    conjugate = FakeUfuncOneArg()
    cosh = FakeUfuncOneArg()
    deg2rad = FakeUfuncOneArg()
    exp2 = FakeUfuncOneArg()
    expm1 = FakeUfuncOneArg()
    fabs = FakeUfuncOneArg()
    frexp = FakeUfuncOneArgBis()
    isfinite = FakeUfuncOneArg()
    isinf = FakeUfuncOneArg()
    log = FakeUfuncOneArg()
    log1p = FakeUfuncOneArg()
    log2 = FakeUfuncOneArg()
    logical_not = FakeUfuncOneArg()
    modf = FakeUfuncOneArgBis()
    negative = FakeUfuncOneArg()
    positive = FakeUfuncOneArg()
    rad2deg = FakeUfuncOneArg()
    reciprocal = FakeUfuncOneArg()
    rint = FakeUfuncOneArg()
    sign = FakeUfuncOneArg()
    signbit = FakeUfuncOneArg()
    sinh = FakeUfuncOneArg()
    spacing = FakeUfuncOneArg()
    square = FakeUfuncOneArg()
    tan = FakeUfuncOneArg()
    tanh = FakeUfuncOneArg()
    trunc = FakeUfuncOneArg()

    # Two args functions with optional kwargs
    bitwise_and = FakeUfuncTwoArgs()
    bitwise_or = FakeUfuncTwoArgs()
    bitwise_xor = FakeUfuncTwoArgs()
    copysign = FakeUfuncTwoArgs()
    divide = FakeUfuncTwoArgs()
    divmod = FakeUfuncTwoArgs()
    equal = FakeUfuncTwoArgs()
    float_power = FakeUfuncTwoArgs()
    floor_divide = FakeUfuncTwoArgs()
    fmax = FakeUfuncTwoArgs()
    fmin = FakeUfuncTwoArgs()
    fmod = FakeUfuncTwoArgs()
    greater = FakeUfuncTwoArgs()
    gcd = FakeUfuncTwoArgs()
    hypot = FakeUfuncTwoArgs()
    heaviside = FakeUfuncTwoArgs()
    lcm = FakeUfuncTwoArgs()
    ldexp = FakeUfuncTwoArgs()
    left_shift = FakeUfuncTwoArgs()
    less = FakeUfuncTwoArgs()
    logaddexp = FakeUfuncTwoArgs()
    logaddexp2 = FakeUfuncTwoArgs()
    logical_and = FakeUfuncTwoArgs()
    logical_or = FakeUfuncTwoArgs()
    logical_xor = FakeUfuncTwoArgs()
    maximum = FakeUfuncTwoArgs()
    minimum = FakeUfuncTwoArgs()
    nextafter = FakeUfuncTwoArgs()
    not_equal = FakeUfuncTwoArgs()
    power = FakeUfuncTwoArgs()
    remainder = FakeUfuncTwoArgs()
    right_shift = FakeUfuncTwoArgs()
    subtract = FakeUfuncTwoArgs()
    true_divide = FakeUfuncTwoArgs()
    """.format(
            opt_args=ufunc_optional_keyword_arguments
        )
    )


astroid.register_module_extender(
    astroid.MANAGER, "numpy.core.umath", numpy_core_umath_transform
)
