from decimal import Decimal as D

from unit_converter.units import UnitPrefix, Unit

# ----------
# Prefix SI
# ----------
PREFIXES = {
    'y': UnitPrefix(symbol='y', name='yocto', factor=D('1E-24')),
    'z': UnitPrefix(symbol='z', name='zepto', factor=D('1E-21')),
    'a': UnitPrefix(symbol='a', name='atto', factor=D('1E-18')),
    'f': UnitPrefix(symbol='f', name='femto', factor=D('1E-15')),
    'p': UnitPrefix(symbol='p', name='pico', factor=D('1E-12')),
    'n': UnitPrefix(symbol='n', name='nano', factor=D('1E-9')),
    'µ': UnitPrefix(symbol='µ', name='micro', factor=D('1E-6')),
    'm': UnitPrefix(symbol='m', name='milli', factor=D('1E-3')),
    'c': UnitPrefix(symbol='c', name='centi', factor=D('1E-2')),
    'd': UnitPrefix(symbol='d', name='deci', factor=D('1E-1')),
    '': UnitPrefix(symbol='', name='', factor=D('1E0')),
    'da': UnitPrefix(symbol='da', name='deca', factor=D('1E+1')),
    'h': UnitPrefix(symbol='h', name='hecto', factor=D('1E+2')),
    'k': UnitPrefix(symbol='k', name='kilo', factor=D('1E+3')),
    'M': UnitPrefix(symbol='M', name='mega', factor=D('1E+6')),
    'G': UnitPrefix(symbol='G', name='giga', factor=D('1E+9')),
    'T': UnitPrefix(symbol='T', name='tera', factor=D('1E+12')),
    'P': UnitPrefix(symbol='P', name='peta', factor=D('1E+15')),
    'E': UnitPrefix(symbol='E', name='exa', factor=D('1E+18')),
    'Z': UnitPrefix(symbol='Z', name='zetta', factor=D('1E+21')),
    'Y': UnitPrefix(symbol='Y', name='yotta', factor=D('1E+24')),
}

# ----------
# Units
# ----------
UNITS = {
    # Basic SI units
    # --------------
    'm': Unit('m', 'meter', L=1),
    'g': Unit('g', 'gram', M=1, coef=D('1E-3')),
    's': Unit('s', 'second', T=1),
    'A': Unit('A', 'ampere', I=1),
    'K': Unit('K', 'kelvin', THETA=1),
    'mol': Unit('mol', 'mole', N=1),
    'cd': Unit('cd', 'candela', J=1),

    # Derived SI units
    # ----------------
    'Hz': Unit('Hz', 'hertz', T=-1),
    'N': Unit('N', 'newton', M=1, L=1, T=-2),
    'Pa': Unit('Pa', 'pascal', M=1, L=-1, T=-2),
    'J': Unit('J', 'joule', M=1, L=2, T=-2),
    'W': Unit('W', 'watt', M=1, L=2, T=-3),
    'C': Unit('C', 'coulomb', T=1, I=1),
    'V': Unit('V', 'volt', M=1, L=2, T=-3, I=-1),
    'Ω': Unit('Ω', 'ohm', M=1, L=2, T=-3, I=-2),
    'S': Unit('S', 'siemens', M=-1, L=-2, T=3, I=2),
    'F': Unit('F', 'farad', M=-1, L=-2, T=4, I=2),
    'T': Unit('T', 'tesla', M=1, T=-2, I=-1),
    'Wb': Unit('Wb', 'weber', M=1, L=2, T=-2, I=-1),
    'H': Unit('H', 'henry', M=1, L=2, T=-2, I=-2),
    '°C': Unit('°C', 'celsius', THETA=1, offset=D('273.15')),
    'rad': Unit('rad', 'radian'),
    'sr': Unit('sr', 'steradian'),
    'lm': Unit('lm', 'lumen', J=1),
    'lx': Unit('lx', 'lux', L=-2, J=1),
    'Bq': Unit('Bq', 'becquerel', T=-1),
    'Gy': Unit('Gy', 'gray', L=2, T=-2),
    'Sv': Unit('Sv', 'sievert', L=2, T=-2),
    'kat': Unit('kat', 'katal', T=-1, N=1),

    # Imperial system
    # ---------------
    '°F': Unit('°F', 'fahrenheit', THETA=1,
               offset=D('273.15') - D('32') / D('1.8'), coef=D('1') / D('1.8')),
    'thou': Unit('th', 'thou', L=1, coef=D('2.54E-5')),
    'inch': Unit('in', 'inch', L=1, coef=D('2.54E-2')),
    'foot': Unit('ft', 'foot', L=1, coef=D('3.048E-1')),
    'yard': Unit('yd', 'yard', L=1, coef=D('9.144E-1')),
    'chain': Unit('ch', 'chain', L=1, coef=D('20.1168')),
    'furlong': Unit('fur', 'furlong', L=1, coef=D('201.168')),
    'mile': Unit('ml', 'mile', L=1, coef=D('1609.344')),
    'league': Unit('lea', 'league', L=1, coef=D('4828.032')),

    # Miscellaneous units
    # -------------------
    'bar': Unit('bar', 'bar', M=1, L=-1, T=-2, coef=D('1E5')),
    'min': Unit('min', 'minute', T=1, coef=D('60')),
    'h': Unit('h', 'hour', T=1, coef=D('3600')),
}
