#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
from Naked.toolshed.file import FileReader

# ------------------------------------------------------------------------------
# PUBLIC
# ------------------------------------------------------------------------------
def generate_hash(filepath):
    """Public function that reads a local file and generates a SHA256 hash digest for it"""
    fr = FileReader(filepath)
    data = fr.read_bin()
    return _calculate_sha256(data)


# ------------------------------------------------------------------------------
# PRIVATE
# ------------------------------------------------------------------------------
def _calculate_sha256(binary_string):
    """Private function that calculates a SHA256 hash digest for a binary string argument"""
    return hashlib.sha256(binary_string).hexdigest()

