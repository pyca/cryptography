import sys
from threading import Lock
import time
import types

from . import values  # retain this import style for testability
from .context_managers import ExceptionCounter, InprogressTracker, Timer
from .metrics_core import (
    Metric, METRIC_LABEL_NAME_RE, METRIC_NAME_RE,
    RESERVED_METRIC_LABEL_NAME_RE,
)
from .registry import REGISTRY
from .utils import floatToGoString, INF

if sys.version_info > (3,):
    unicode = str
    create_bound_method = types.MethodType
else:
    def create_bound_method(func, obj):
        return types.MethodType(func, obj, obj.__class__)


def _build_full_name(metric_type, name, namespace, subsystem, unit):
    full_name = ''
    if namespace:
        full_name += namespace + '_'
    if subsystem:
        full_name += subsystem + '_'
    full_name += name
    if metric_type == 'counter' and full_name.endswith('_total'):
        full_name = full_name[:-6]  # Munge to OpenMetrics.
    if unit and not full_name.endswith("_" + unit):
        full_name += "_" + unit
    if unit and metric_type in ('info', 'stateset'):
        raise ValueError('Metric name is of a type that cannot have a unit: ' + full_name)
    return full_name


def _validate_labelnames(cls, labelnames):
    labelnames = tuple(labelnames)
    for l in labelnames:
        if not METRIC_LABEL_NAME_RE.match(l):
            raise ValueError('Invalid label metric name: ' + l)
        if RESERVED_METRIC_LABEL_NAME_RE.match(l):
            raise ValueError('Reserved label metric name: ' + l)
        if l in cls._reserved_labelnames:
            raise ValueError('Reserved label metric name: ' + l)
    return labelnames


class MetricWrapperBase(object):
    _type = None
    _reserved_labelnames = ()

    def _is_observable(self):
        # Whether this metric is observable, i.e.
        # * a metric without label names and values, or
        # * the child of a labelled metric.
        return not self._labelnames or (self._labelnames and self._labelvalues)

    def _raise_if_not_observable(self):
        # Functions that mutate the state of the metric, for example incrementing
        # a counter, will fail if the metric is not observable, because only if a
        # metric is observable will the value be initialized.
        if not self._is_observable():
            raise ValueError('%s metric is missing label values' % str(self._type))

    def _is_parent(self):
        return self._labelnames and not self._labelvalues

    def _get_metric(self):
        return Metric(self._name, self._documentation, self._type, self._unit)

    def describe(self):
        return [self._get_metric()]

    def collect(self):
        metric = self._get_metric()
        for suffix, labels, value in self._samples():
            metric.add_sample(self._name + suffix, labels, value)
        return [metric]

    def __str__(self):
        return "{0}:{1}".format(self._type, self._name)

    def __repr__(self):
        metric_type = type(self)
        return "{0}.{1}({2})".format(metric_type.__module__, metric_type.__name__, self._name)

    def __init__(self,
                 name,
                 documentation,
                 labelnames=(),
                 namespace='',
                 subsystem='',
                 unit='',
                 registry=REGISTRY,
                 labelvalues=None,
                 ):
        self._name = _build_full_name(self._type, name, namespace, subsystem, unit)
        self._labelnames = _validate_labelnames(self, labelnames)
        self._labelvalues = tuple(labelvalues or ())
        self._kwargs = {}
        self._documentation = documentation
        self._unit = unit

        if not METRIC_NAME_RE.match(self._name):
            raise ValueError('Invalid metric name: ' + self._name)

        if self._is_parent():
            # Prepare the fields needed for child metrics.
            self._lock = Lock()
            self._metrics = {}

        if self._is_observable():
            self._metric_init()

        if not self._labelvalues:
            # Register the multi-wrapper parent metric, or if a label-less metric, the whole shebang.
            if registry:
                registry.register(self)

    def labels(self, *labelvalues, **labelkwargs):
        """Return the child for the given labelset.

        All metrics can have labels, allowing grouping of related time series.
        Taking a counter as an example:

            from prometheus_client import Counter

            c = Counter('my_requests_total', 'HTTP Failures', ['method', 'endpoint'])
            c.labels('get', '/').inc()
            c.labels('post', '/submit').inc()

        Labels can also be provided as keyword arguments:

            from prometheus_client import Counter

            c = Counter('my_requests_total', 'HTTP Failures', ['method', 'endpoint'])
            c.labels(method='get', endpoint='/').inc()
            c.labels(method='post', endpoint='/submit').inc()

        See the best practices on [naming](http://prometheus.io/docs/practices/naming/)
        and [labels](http://prometheus.io/docs/practices/instrumentation/#use-labels).
        """
        if not self._labelnames:
            raise ValueError('No label names were set when constructing %s' % self)

        if self._labelvalues:
            raise ValueError('%s already has labels set (%s); can not chain calls to .labels()' % (
                self,
                dict(zip(self._labelnames, self._labelvalues))
            ))

        if labelvalues and labelkwargs:
            raise ValueError("Can't pass both *args and **kwargs")

        if labelkwargs:
            if sorted(labelkwargs) != sorted(self._labelnames):
                raise ValueError('Incorrect label names')
            labelvalues = tuple(unicode(labelkwargs[l]) for l in self._labelnames)
        else:
            if len(labelvalues) != len(self._labelnames):
                raise ValueError('Incorrect label count')
            labelvalues = tuple(unicode(l) for l in labelvalues)
        with self._lock:
            if labelvalues not in self._metrics:
                self._metrics[labelvalues] = self.__class__(
                    self._name,
                    documentation=self._documentation,
                    labelnames=self._labelnames,
                    unit=self._unit,
                    labelvalues=labelvalues,
                    **self._kwargs
                )
            return self._metrics[labelvalues]

    def remove(self, *labelvalues):
        if not self._labelnames:
            raise ValueError('No label names were set when constructing %s' % self)

        """Remove the given labelset from the metric."""
        if len(labelvalues) != len(self._labelnames):
            raise ValueError('Incorrect label count (expected %d, got %s)' % (len(self._labelnames), labelvalues))
        labelvalues = tuple(unicode(l) for l in labelvalues)
        with self._lock:
            del self._metrics[labelvalues]

    def _samples(self):
        if self._is_parent():
            return self._multi_samples()
        else:
            return self._child_samples()

    def _multi_samples(self):
        with self._lock:
            metrics = self._metrics.copy()
        for labels, metric in metrics.items():
            series_labels = list(zip(self._labelnames, labels))
            for suffix, sample_labels, value in metric._samples():
                yield (suffix, dict(series_labels + list(sample_labels.items())), value)

    def _child_samples(self):  # pragma: no cover
        raise NotImplementedError('_child_samples() must be implemented by %r' % self)

    def _metric_init(self):  # pragma: no cover
        """
        Initialize the metric object as a child, i.e. when it has labels (if any) set.

        This is factored as a separate function to allow for deferred initialization.
        """
        raise NotImplementedError('_metric_init() must be implemented by %r' % self)


class Counter(MetricWrapperBase):
    """A Counter tracks counts of events or running totals.

    Example use cases for Counters:
    - Number of requests processed
    - Number of items that were inserted into a queue
    - Total amount of data that a system has processed

    Counters can only go up (and be reset when the process restarts). If your use case can go down,
    you should use a Gauge instead.

    An example for a Counter:

        from prometheus_client import Counter

        c = Counter('my_failures_total', 'Description of counter')
        c.inc()     # Increment by 1
        c.inc(1.6)  # Increment by given value

    There are utilities to count exceptions raised:

        @c.count_exceptions()
        def f():
            pass

        with c.count_exceptions():
            pass

        # Count only one type of exception
        with c.count_exceptions(ValueError):
            pass
    """
    _type = 'counter'

    def _metric_init(self):
        self._value = values.ValueClass(self._type, self._name, self._name + '_total', self._labelnames,
                                        self._labelvalues)
        self._created = time.time()

    def inc(self, amount=1):
        """Increment counter by the given amount."""
        if amount < 0:
            raise ValueError('Counters can only be incremented by non-negative amounts.')
        self._value.inc(amount)

    def count_exceptions(self, exception=Exception):
        """Count exceptions in a block of code or function.

        Can be used as a function decorator or context manager.
        Increments the counter when an exception of the given
        type is raised up out of the code.
        """
        self._raise_if_not_observable()
        return ExceptionCounter(self, exception)

    def _child_samples(self):
        return (
            ('_total', {}, self._value.get()),
            ('_created', {}, self._created),
        )


class Gauge(MetricWrapperBase):
    """Gauge metric, to report instantaneous values.

     Examples of Gauges include:
        - Inprogress requests
        - Number of items in a queue
        - Free memory
        - Total memory
        - Temperature

     Gauges can go both up and down.

        from prometheus_client import Gauge

        g = Gauge('my_inprogress_requests', 'Description of gauge')
        g.inc()      # Increment by 1
        g.dec(10)    # Decrement by given value
        g.set(4.2)   # Set to a given value

     There are utilities for common use cases:

        g.set_to_current_time()   # Set to current unixtime

        # Increment when entered, decrement when exited.
        @g.track_inprogress()
        def f():
            pass

        with g.track_inprogress():
            pass

     A Gauge can also take its value from a callback:

        d = Gauge('data_objects', 'Number of objects')
        my_dict = {}
        d.set_function(lambda: len(my_dict))
    """
    _type = 'gauge'
    _MULTIPROC_MODES = frozenset(('min', 'max', 'livesum', 'liveall', 'all'))

    def __init__(self,
                 name,
                 documentation,
                 labelnames=(),
                 namespace='',
                 subsystem='',
                 unit='',
                 registry=REGISTRY,
                 labelvalues=None,
                 multiprocess_mode='all',
                 ):
        self._multiprocess_mode = multiprocess_mode
        if multiprocess_mode not in self._MULTIPROC_MODES:
            raise ValueError('Invalid multiprocess mode: ' + multiprocess_mode)
        super(Gauge, self).__init__(
            name=name,
            documentation=documentation,
            labelnames=labelnames,
            namespace=namespace,
            subsystem=subsystem,
            unit=unit,
            registry=registry,
            labelvalues=labelvalues,
        )
        self._kwargs['multiprocess_mode'] = self._multiprocess_mode

    def _metric_init(self):
        self._value = values.ValueClass(
            self._type, self._name, self._name, self._labelnames, self._labelvalues,
            multiprocess_mode=self._multiprocess_mode
        )

    def inc(self, amount=1):
        """Increment gauge by the given amount."""
        self._value.inc(amount)

    def dec(self, amount=1):
        """Decrement gauge by the given amount."""
        self._value.inc(-amount)

    def set(self, value):
        """Set gauge to the given value."""
        self._value.set(float(value))

    def set_to_current_time(self):
        """Set gauge to the current unixtime."""
        self.set(time.time())

    def track_inprogress(self):
        """Track inprogress blocks of code or functions.

        Can be used as a function decorator or context manager.
        Increments the gauge when the code is entered,
        and decrements when it is exited.
        """
        self._raise_if_not_observable()
        return InprogressTracker(self)

    def time(self):
        """Time a block of code or function, and set the duration in seconds.

        Can be used as a function decorator or context manager.
        """
        self._raise_if_not_observable()
        return Timer(self.set)

    def set_function(self, f):
        """Call the provided function to return the Gauge value.

        The function must return a float, and may be called from
        multiple threads. All other methods of the Gauge become NOOPs.
        """

        def samples(self):
            return (('', {}, float(f())),)

        self._child_samples = create_bound_method(samples, self)

    def _child_samples(self):
        return (('', {}, self._value.get()),)


class Summary(MetricWrapperBase):
    """A Summary tracks the size and number of events.

    Example use cases for Summaries:
    - Response latency
    - Request size

    Example for a Summary:

        from prometheus_client import Summary

        s = Summary('request_size_bytes', 'Request size (bytes)')
        s.observe(512)  # Observe 512 (bytes)

    Example for a Summary using time:

        from prometheus_client import Summary

        REQUEST_TIME = Summary('response_latency_seconds', 'Response latency (seconds)')

        @REQUEST_TIME.time()
        def create_response(request):
          '''A dummy function'''
          time.sleep(1)

    Example for using the same Summary object as a context manager:

        with REQUEST_TIME.time():
            pass  # Logic to be timed
    """
    _type = 'summary'
    _reserved_labelnames = ['quantile']

    def _metric_init(self):
        self._count = values.ValueClass(self._type, self._name, self._name + '_count', self._labelnames,
                                        self._labelvalues)
        self._sum = values.ValueClass(self._type, self._name, self._name + '_sum', self._labelnames, self._labelvalues)
        self._created = time.time()

    def observe(self, amount):
        """Observe the given amount."""
        self._count.inc(1)
        self._sum.inc(amount)

    def time(self):
        """Time a block of code or function, and observe the duration in seconds.

        Can be used as a function decorator or context manager.
        """
        self._raise_if_not_observable()
        return Timer(self.observe)

    def _child_samples(self):
        return (
            ('_count', {}, self._count.get()),
            ('_sum', {}, self._sum.get()),
            ('_created', {}, self._created))


class Histogram(MetricWrapperBase):
    """A Histogram tracks the size and number of events in buckets.

    You can use Histograms for aggregatable calculation of quantiles.

    Example use cases:
    - Response latency
    - Request size

    Example for a Histogram:

        from prometheus_client import Histogram

        h = Histogram('request_size_bytes', 'Request size (bytes)')
        h.observe(512)  # Observe 512 (bytes)

    Example for a Histogram using time:

        from prometheus_client import Histogram

        REQUEST_TIME = Histogram('response_latency_seconds', 'Response latency (seconds)')

        @REQUEST_TIME.time()
        def create_response(request):
          '''A dummy function'''
          time.sleep(1)

    Example of using the same Histogram object as a context manager:

        with REQUEST_TIME.time():
            pass  # Logic to be timed

    The default buckets are intended to cover a typical web/rpc request from milliseconds to seconds.
    They can be overridden by passing `buckets` keyword argument to `Histogram`.
    """
    _type = 'histogram'
    _reserved_labelnames = ['le']
    DEFAULT_BUCKETS = (.005, .01, .025, .05, .075, .1, .25, .5, .75, 1.0, 2.5, 5.0, 7.5, 10.0, INF)

    def __init__(self,
                 name,
                 documentation,
                 labelnames=(),
                 namespace='',
                 subsystem='',
                 unit='',
                 registry=REGISTRY,
                 labelvalues=None,
                 buckets=DEFAULT_BUCKETS,
                 ):
        self._prepare_buckets(buckets)
        super(Histogram, self).__init__(
            name=name,
            documentation=documentation,
            labelnames=labelnames,
            namespace=namespace,
            subsystem=subsystem,
            unit=unit,
            registry=registry,
            labelvalues=labelvalues,
        )
        self._kwargs['buckets'] = buckets

    def _prepare_buckets(self, buckets):
        buckets = [float(b) for b in buckets]
        if buckets != sorted(buckets):
            # This is probably an error on the part of the user,
            # so raise rather than sorting for them.
            raise ValueError('Buckets not in sorted order')
        if buckets and buckets[-1] != INF:
            buckets.append(INF)
        if len(buckets) < 2:
            raise ValueError('Must have at least two buckets')
        self._upper_bounds = buckets

    def _metric_init(self):
        self._buckets = []
        self._created = time.time()
        bucket_labelnames = self._labelnames + ('le',)
        self._sum = values.ValueClass(self._type, self._name, self._name + '_sum', self._labelnames, self._labelvalues)
        for b in self._upper_bounds:
            self._buckets.append(values.ValueClass(
                self._type,
                self._name,
                self._name + '_bucket',
                bucket_labelnames,
                self._labelvalues + (floatToGoString(b),))
            )

    def observe(self, amount):
        """Observe the given amount."""
        self._sum.inc(amount)
        for i, bound in enumerate(self._upper_bounds):
            if amount <= bound:
                self._buckets[i].inc(1)
                break

    def time(self):
        """Time a block of code or function, and observe the duration in seconds.

        Can be used as a function decorator or context manager.
        """
        return Timer(self.observe)

    def _child_samples(self):
        samples = []
        acc = 0
        for i, bound in enumerate(self._upper_bounds):
            acc += self._buckets[i].get()
            samples.append(('_bucket', {'le': floatToGoString(bound)}, acc))
        samples.append(('_count', {}, acc))
        if self._upper_bounds[0] >= 0:
            samples.append(('_sum', {}, self._sum.get()))
        samples.append(('_created', {}, self._created))
        return tuple(samples)


class Info(MetricWrapperBase):
    """Info metric, key-value pairs.

     Examples of Info include:
        - Build information
        - Version information
        - Potential target metadata

     Example usage:
        from prometheus_client import Info

        i = Info('my_build', 'Description of info')
        i.info({'version': '1.2.3', 'buildhost': 'foo@bar'})

     Info metrics do not work in multiprocess mode.
    """
    _type = 'info'

    def _metric_init(self):
        self._labelname_set = set(self._labelnames)
        self._lock = Lock()
        self._value = {}

    def info(self, val):
        """Set info metric."""
        if self._labelname_set.intersection(val.keys()):
            raise ValueError('Overlapping labels for Info metric, metric: %s child: %s' % (
                self._labelnames, val))
        with self._lock:
            self._value = dict(val)

    def _child_samples(self):
        with self._lock:
            return (('_info', self._value, 1.0,),)


class Enum(MetricWrapperBase):
    """Enum metric, which of a set of states is true.

     Example usage:
        from prometheus_client import Enum

        e = Enum('task_state', 'Description of enum',
          states=['starting', 'running', 'stopped'])
        e.state('running')

     The first listed state will be the default.
     Enum metrics do not work in multiprocess mode.
    """
    _type = 'stateset'

    def __init__(self,
                 name,
                 documentation,
                 labelnames=(),
                 namespace='',
                 subsystem='',
                 unit='',
                 registry=REGISTRY,
                 labelvalues=None,
                 states=None,
                 ):
        super(Enum, self).__init__(
            name=name,
            documentation=documentation,
            labelnames=labelnames,
            namespace=namespace,
            subsystem=subsystem,
            unit=unit,
            registry=registry,
            labelvalues=labelvalues,
        )
        if name in labelnames:
            raise ValueError('Overlapping labels for Enum metric: %s' % (name,))
        if not states:
            raise ValueError('No states provided for Enum metric: %s' % (name,))
        self._kwargs['states'] = self._states = states

    def _metric_init(self):
        self._value = 0
        self._lock = Lock()

    def state(self, state):
        """Set enum metric state."""
        self._raise_if_not_observable()
        with self._lock:
            self._value = self._states.index(state)

    def _child_samples(self):
        with self._lock:
            return [
                ('', {self._name: s}, 1 if i == self._value else 0,)
                for i, s
                in enumerate(self._states)
            ]
