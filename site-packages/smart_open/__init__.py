# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#

"""
Utilities for streaming to/from several file-like data storages: S3 / HDFS / local
filesystem / compressed files, and many more, using a simple, Pythonic API.

The streaming makes heavy use of generators and pipes, to avoid loading
full file contents into memory, allowing work with arbitrarily large files.

The main functions are:

* `open()`, which opens the given file for reading/writing
* `parse_uri()`
* `s3_iter_bucket()`, which goes over all keys in an S3 bucket in parallel
* `register_compressor()`, which registers callbacks for transparent compressor handling

"""

import logging

#
# Prevent regression of #474 and #475
#
logging.getLogger(__name__).addHandler(logging.NullHandler())

from smart_open import version  # noqa: E402
from .smart_open_lib import open, parse_uri, smart_open, register_compressor  # noqa: E402
from .s3 import iter_bucket as s3_iter_bucket  # noqa: E402

__all__ = [
    'open',
    'parse_uri',
    'register_compressor',
    's3_iter_bucket',
    'smart_open',
]

__version__ = version.__version__
