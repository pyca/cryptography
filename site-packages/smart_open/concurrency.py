# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#

"""Common functionality for concurrent processing.

The main entry point is :func:`create_pool`.
"""

import contextlib
import logging
import warnings

logger = logging.getLogger(__name__)

# AWS Lambda environments do not support multiprocessing.Queue or multiprocessing.Pool.
# However they do support Threads and therefore concurrent.futures's ThreadPoolExecutor.
# We use this flag to allow python 2 backward compatibility, where concurrent.futures doesn't exist.
_CONCURRENT_FUTURES = False
try:
    import concurrent.futures
    _CONCURRENT_FUTURES = True
except ImportError:
    warnings.warn("concurrent.futures could not be imported and won't be used")

# Multiprocessing is unavailable in App Engine (and possibly other sandboxes).
# The only method currently relying on it is iter_bucket, which is instructed
# whether to use it by the MULTIPROCESSING flag.
_MULTIPROCESSING = False
try:
    import multiprocessing.pool
    _MULTIPROCESSING = True
except ImportError:
    warnings.warn("multiprocessing could not be imported and won't be used")


class DummyPool(object):
    """A class that mimics multiprocessing.pool.Pool for our purposes."""
    def imap_unordered(self, function, items):
        return map(function, items)

    def terminate(self):
        pass


class ConcurrentFuturesPool(object):
    """A class that mimics multiprocessing.pool.Pool but uses concurrent futures instead of processes."""
    def __init__(self, max_workers):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers)

    def imap_unordered(self, function, items):
        futures = [self.executor.submit(function, item) for item in items]
        for future in concurrent.futures.as_completed(futures):
            yield future.result()

    def terminate(self):
        self.executor.shutdown(wait=True)


@contextlib.contextmanager
def create_pool(processes=1):
    if _MULTIPROCESSING and processes:
        logger.info("creating multiprocessing pool with %i workers", processes)
        pool = multiprocessing.pool.Pool(processes=processes)
    elif _CONCURRENT_FUTURES and processes:
        logger.info("creating concurrent futures pool with %i workers", processes)
        pool = ConcurrentFuturesPool(max_workers=processes)
    else:
        logger.info("creating dummy pool")
        pool = DummyPool()
    yield pool
    pool.terminate()
