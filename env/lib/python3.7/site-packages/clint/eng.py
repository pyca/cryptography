# -*- coding: utf-8 -*-

"""
clint.eng
~~~~~~~~~

This module provides English language string helpers.

"""
from __future__ import print_function

MORON_MODE = False
COMMA = ','
CONJUNCTION = 'and'
SPACE = ' '

try:
    unicode
except NameError:
    unicode = str


def join(l, conj=CONJUNCTION, im_a_moron=MORON_MODE, separator=COMMA):
    """Joins lists of words. Oxford comma and all."""

    collector = []
    left = len(l)
    separator = separator + SPACE
    conj = conj + SPACE

    for _l in l[:]:

        left += -1

        collector.append(_l)
        if left == 1:
            if len(l) == 2 or im_a_moron:
                collector.append(SPACE)
            else:
                collector.append(separator)

            collector.append(conj)

        elif left is not 0:
            collector.append(separator)

    return unicode(str().join(collector))

if __name__ == '__main__':
    print(join(['blue', 'red', 'yellow'], conj='or', im_a_moron=True))
    print(join(['blue', 'red', 'yellow'], conj='or'))
    print(join(['blue', 'red'], conj='or'))
    print(join(['blue', 'red'], conj='and'))
    print(join(['blue'], conj='and'))
    print(join(['blue', 'red', 'yellow', 'green', 'ello'], conj='and'))
