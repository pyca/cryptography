# -*- coding: utf-8 -*-

"""
Example
-------
These examples can be run with:

    $ python examples/examples.py


"""

import sys
import numpy as np

from unit import Unit, ArrayUnit

def ex1():
    m = Unit('m')
    s = Unit('s', -2)
    arr = np.linspace(1,10,10, dtype=float)
    a = ArrayUnit(arr, m)
    b = ArrayUnit(arr**2, s)
    ArrayUnit.is_strict = True
    print(a, '\n+\n', 1, '\n=\n', a + 1)
    print('__________________________________________')
    print(a, '\n-\n', arr, '\n=\n', a - arr)
    print('__________________________________________')
    print(a, '\n*\n', b, '\n=\n', a * b)
    print('__________________________________________')
    print(b, '\n//\n', a, '\n=\n', b / a)

def ex2():
    newton = Unit({
        'kg': 1,
        'm': 1,
        's': -2
    })
    joule = newton * Unit('m')
    pascal = Unit({
        'kg': 1,
        'm': -1,
        's': -2
    })

    measure1 = ArrayUnit(np.random.random((3, 4)), joule)
    measure2 = ArrayUnit(np.random.random((3, 4)), pascal)
    print(measure1 / measure2)
    print(measure1 + 3)



def main():
    if len(sys.argv) >= 2:
        if sys.argv[1] == '1':
            ex1()
        elif sys.argv[1] == '2':
            ex2()
    else:
        print("You should indicate which example to run [1 or 2]")
   

if __name__ == '__main__':
    main()

# %%
