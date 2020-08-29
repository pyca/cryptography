from __future__ import unicode_literals

import gc
import platform

from .metrics_core import CounterMetricFamily
from .registry import REGISTRY


class GCCollector(object):
    """Collector for Garbage collection statistics."""

    def __init__(self, registry=REGISTRY):
        if not hasattr(gc, 'get_stats') or platform.python_implementation() != 'CPython':
            return
        registry.register(self)

    def collect(self):
        collected = CounterMetricFamily(
            'python_gc_objects_collected',
            'Objects collected during gc',
            labels=['generation'],
        )
        uncollectable = CounterMetricFamily(
            'python_gc_objects_uncollectable',
            'Uncollectable object found during GC',
            labels=['generation'],
        )

        collections = CounterMetricFamily(
            'python_gc_collections',
            'Number of times this generation was collected',
            labels=['generation'],
        )

        for generation, stat in enumerate(gc.get_stats()):
            generation = str(generation)
            collected.add_metric([generation], value=stat['collected'])
            uncollectable.add_metric([generation], value=stat['uncollectable'])
            collections.add_metric([generation], value=stat['collections'])

        return [collected, uncollectable, collections]


GC_COLLECTOR = GCCollector()
"""Default GCCollector in default Registry REGISTRY."""
