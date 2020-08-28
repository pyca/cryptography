# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#

"""Some universal constants that are common to I/O operations."""


READ_BINARY = 'rb'

WRITE_BINARY = 'wb'

BINARY_MODES = (READ_BINARY, WRITE_BINARY)

BINARY_NEWLINE = b'\n'

WHENCE_START = 0

WHENCE_CURRENT = 1

WHENCE_END = 2

WHENCE_CHOICES = (WHENCE_START, WHENCE_CURRENT, WHENCE_END)
