#!/usr/bin/python

from . import exposition
from . import gc_collector
from . import metrics
from . import metrics_core
from . import platform_collector
from . import process_collector
from . import registry

__all__ = ['Counter', 'Gauge', 'Summary', 'Histogram', 'Info', 'Enum']

CollectorRegistry = registry.CollectorRegistry
REGISTRY = registry.REGISTRY
Metric = metrics_core.Metric
Counter = metrics.Counter
Gauge = metrics.Gauge
Summary = metrics.Summary
Histogram = metrics.Histogram
Info = metrics.Info
Enum = metrics.Enum

CONTENT_TYPE_LATEST = exposition.CONTENT_TYPE_LATEST
generate_latest = exposition.generate_latest
MetricsHandler = exposition.MetricsHandler
make_wsgi_app = exposition.make_wsgi_app
try:
    # Python >3.5 only
    make_asgi_app = exposition.make_asgi_app
except:
    pass
start_http_server = exposition.start_http_server
start_wsgi_server = exposition.start_wsgi_server
write_to_textfile = exposition.write_to_textfile
push_to_gateway = exposition.push_to_gateway
pushadd_to_gateway = exposition.pushadd_to_gateway
delete_from_gateway = exposition.delete_from_gateway
instance_ip_grouping_key = exposition.instance_ip_grouping_key

ProcessCollector = process_collector.ProcessCollector
PROCESS_COLLECTOR = process_collector.PROCESS_COLLECTOR

PlatformCollector = platform_collector.PlatformCollector
PLATFORM_COLLECTOR = platform_collector.PLATFORM_COLLECTOR

GCCollector = gc_collector.GCCollector
GC_COLLECTOR = gc_collector.GC_COLLECTOR

if __name__ == '__main__':
    c = Counter('cc', 'A counter')
    c.inc()

    g = Gauge('gg', 'A gauge')
    g.set(17)

    s = Summary('ss', 'A summary', ['a', 'b'])
    s.labels('c', 'd').observe(17)

    h = Histogram('hh', 'A histogram')
    h.observe(.6)

    start_http_server(8000)
    import time

    while True:
        time.sleep(1)
