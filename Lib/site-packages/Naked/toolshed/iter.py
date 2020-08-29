#!/usr/bin/env python
# encoding: utf-8

import itertools

#------------------------------------------------------------------------------
# [ chain_iter method ] (iterable items of type contained in multiple list arguments)
#   Generator that returns iterable for each item in the multiple list arguments in sequence
#------------------------------------------------------------------------------
def chain_iter(self, *lists):
    return itertools.chain(*lists)

if __name__ == '__main__':
    pass
