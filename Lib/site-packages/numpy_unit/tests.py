# -*- coding: utf-8 -*-

import unittest

from random import randint
import numpy as np

from unit import Unit, ArrayUnit

class UnitTest(unittest.TestCase):

    def setUp(self):
        self.m = Unit('m')
        self.s = Unit('s', -1)
        self.c = Unit({'m': 1, 's': 1, 'j': 2})

        self.m_ = Unit({'m': 1, 'useless': 0})

    def test_eq(self):
        self.assertNotEqual(self.m, self.s)
        self.assertNotEqual(self.m, self.c)
        self.assertEqual(self.m, self.m_)
        self.assertEqual(self.s, self.s)

    def test_constructor(self):
        # from Unit
        self.assertEqual(self.m, Unit(self.m_))
        #from str
        self.assertEqual(Unit('str'), Unit('str', 1))
        self.assertEqual(Unit('str'), Unit({'str': 1}))
        # from dict
        self.assertEqual(self.m, Unit({'m': 1}))
        # from bad dict
        with self.assertWarns(Warning):
            self.assertEqual(Unit({5: 5, 'm': 1}), Unit())
        #from everything else => Empty
        self.assertEqual(Unit(1), Unit())
        self.assertEqual(Unit([0,1,2]), Unit())
        self.assertEqual(Unit(lambda x: x), Unit())

    def test_mul(self):
        self.assertEqual(self.m * self.s * self.c, self.c * self.m * self.s)
        self.assertEqual(2 * self.m, self.m)
        self.assertEqual(self.m * 2, self.m)

        self.assertEqual(self.m * Unit({'s': 1, 'j': 2}), self.c)

    def test_truediv(self):
        # __truediv__ with Unit()
        self.assertEqual(self.m, self.m / 2)
        self.assertEqual(self.m / 2, self.m / [6, 9])

        # __rtruediv__ with Unit()
        self.assertEqual(Unit() / self.m, 1 / self.m)
        self.assertEqual(1 / self.m, [6, 9] / self.m)

        # div between 2 Unit
        self.assertEqual(self.m / self.m, Unit())
        self.assertEqual(self.m / self.s, Unit({'m': 1, 's': 1}))
        self.assertEqual(self.c / self.m / self.s, Unit({'s': 2, 'j': 2}))
        self.assertEqual(self.m / self.c, Unit({'s': -1, 'j': -2}))

    def test_floordiv(self):
        # copy pasta of test_truediv with "//" instead of "/"
        # __floordiv__ with Unit()
        self.assertEqual(self.m, self.m // 2)
        self.assertEqual(self.m // 2, self.m // [6, 9])

        # __rfloordiv__ with Unit()
        self.assertEqual(Unit() // self.m, 1 // self.m)
        self.assertEqual(1 // self.m, [6, 9] // self.m)

        # div between 2 Unit
        self.assertEqual(self.m // self.m, Unit())
        self.assertEqual(self.m // self.s, Unit({'m': 1, 's': 1}))
        self.assertEqual(self.c // self.m // self.s, Unit({'s': 2, 'j': 2}))
        self.assertEqual(self.m // self.c, Unit({'s': -1, 'j': -2}))

    def test_pow(self):
        # test 0
        self.assertEqual(Unit(), self.c ** 0)

        n = randint(1, 100)
        # test positive int
        res = Unit()
        for _ in range(n):
            res = res * self.c
        self.assertEqual(res, self.c ** n)

        # test negative int
        res = Unit()
        for _ in range(n):
            res = res / self.c
        self.assertEqual(res, self.c ** (-n))

        # test float
        self.assertEqual(self.c ** 3.141592, Unit({'m': 1 * 3.141592, 's': 1 * 3.141592, 'j': 2 * 3.141592}))
        self.assertEqual(self.m ** (-3.141592), Unit('m', -3.141592))


class ArrayUnitTest(unittest.TestCase):

    def setUp(self):
        ArrayUnit.is_strict = True

        self.arr1 = np.linspace(1, 9, 9).reshape(3, 3)
        self.arr2 = self.arr1 - 5
        self.m = Unit('m')
        self.s = Unit('s', -2)

        self.a = ArrayUnit(self.arr1, self.m)
        self.b = ArrayUnit(self.arr2, self.s)

    def test_eq(self):
        self.assertEqual(self.a, self.a)
        self.assertNotEqual(self.a, self.b)
        self.assertEqual(self.arr1, ArrayUnit(self.arr1, Unit()))
        self.assertEqual(ArrayUnit(self.arr1, Unit()), ArrayUnit(self.arr1, None))
    
    def test_add(self):
        self.assertEqual(self.a + 1, 1 + self.a)
        self.assertEqual(self.b + self.b, ArrayUnit(2 * self.arr2, Unit('s', -2)))
        
        ArrayUnit.is_strict = False
        # __add__
        with self.assertWarns(Warning):
            self.assertEqual(self.a + self.b, self.a + self.arr2) # a and b got different units, warnings, but a's unit is kept
        # __radd__
        with self.assertWarns(Warning):
            self.assertEqual(self.b + self.a, self.arr1 + self.b)
        
        ArrayUnit.is_strict = True
        with self.assertRaises(ValueError):
            self.a + self.b
    
    def test_sub(self):
        self.assertEqual(self.a - 1, ArrayUnit(self.arr1 - 1, self.m))
        self.assertEqual(self.b - self.b, ArrayUnit(0 * self.arr2, Unit('s', -2)))
        
        ArrayUnit.is_strict = False
        # __sub__
        with self.assertWarns(Warning):
            self.assertEqual(self.a - self.b, self.a - self.arr2) # a and b got different units, warnings, but a's unit is kept
        # __rsub__
        with self.assertWarns(Warning):
            self.assertEqual(self.b - self.a, self.b - self.arr1)
            self.assertNotEqual(self.b - self.a, self.arr2 - self.a) # unit will conflict (b vs a)
        

        ArrayUnit.is_strict = True
        with self.assertRaises(ValueError):
            self.a - self.b

    def test_mul(self):
        self.assertEqual(self.a * self.b, self.b * self.a)
        self.assertEqual(3 * self.a, self.a * 3)
        self.assertEqual(self.a, self.a * np.ones(self.a.shape))
    
    def test_div(self):
        self.a += 0.001 # avoid division by 0
        self.b += 0.001
        self.assertEqual(self.a / self.b, ArrayUnit(self.arr1 / self.arr2, self.m / self.s))
        self.assertEqual(self.a // self.b, ArrayUnit(self.arr1 // self.arr2, self.m / self.s))
        self.assertEqual(3 / self.a, ArrayUnit(3 / self.arr1, Unit('m', -1)))
        self.assertEqual(3 // self.a, ArrayUnit(3 // self.arr1, Unit('m', -1)))
        self.assertEqual(self.a, self.a / np.ones(self.a.shape))
    
    def test_mod(self):
        self.assertEqual(self.a % self.a, ArrayUnit(np.zeros(self.a.shape), self.a.unit))
        self.assertEqual(self.a % self.arr1, self.a % self.a)

        ArrayUnit.is_strict = False
        with self.assertWarns(Warning):
            self.assertEqual((self.a % self.b).unit, self.a.unit)
        ArrayUnit.is_strict = True
        with self.assertRaises(ValueError):
            self.assertEqual((self.a % self.b).unit, self.a.unit)

    def test_pow(self):
        self.b += 0.1 # avoid division by 0
        self.assertEqual(self.a ** 4, self.a * self.a * self.a * self.a)
        self.assertEqual(self.a ** 0.5, ArrayUnit(np.sqrt(self.arr1), Unit('m', 0.5)))
        self.assertEqual(self.b ** -5, 1 / (self.b ** 5))


unittest.main()
