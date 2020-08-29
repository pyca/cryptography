import re

from .samples import Sample

METRIC_TYPES = (
    'counter', 'gauge', 'summary', 'histogram',
    'gaugehistogram', 'unknown', 'info', 'stateset',
)
METRIC_NAME_RE = re.compile(r'^[a-zA-Z_:][a-zA-Z0-9_:]*$')
METRIC_LABEL_NAME_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
RESERVED_METRIC_LABEL_NAME_RE = re.compile(r'^__.*$')


class Metric(object):
    """A single metric family and its samples.

    This is intended only for internal use by the instrumentation client.

    Custom collectors should use GaugeMetricFamily, CounterMetricFamily
    and SummaryMetricFamily instead.
    """

    def __init__(self, name, documentation, typ, unit=''):
        if unit and not name.endswith("_" + unit):
            name += "_" + unit
        if not METRIC_NAME_RE.match(name):
            raise ValueError('Invalid metric name: ' + name)
        self.name = name
        self.documentation = documentation
        self.unit = unit
        if typ == 'untyped':
            typ = 'unknown'
        if typ not in METRIC_TYPES:
            raise ValueError('Invalid metric type: ' + typ)
        self.type = typ
        self.samples = []

    def add_sample(self, name, labels, value, timestamp=None, exemplar=None):
        """Add a sample to the metric.

        Internal-only, do not use."""
        self.samples.append(Sample(name, labels, value, timestamp, exemplar))

    def __eq__(self, other):
        return (isinstance(other, Metric) and
                self.name == other.name and
                self.documentation == other.documentation and
                self.type == other.type and
                self.unit == other.unit and
                self.samples == other.samples)

    def __repr__(self):
        return "Metric(%s, %s, %s, %s, %s)" % (
            self.name,
            self.documentation,
            self.type,
            self.unit,
            self.samples,
        )


class UnknownMetricFamily(Metric):
    """A single unknown metric and its samples.
    For use by custom collectors.
    """

    def __init__(self, name, documentation, value=None, labels=None, unit=''):
        Metric.__init__(self, name, documentation, 'unknown', unit)
        if labels is not None and value is not None:
            raise ValueError('Can only specify at most one of value and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if value is not None:
            self.add_metric([], value)

    def add_metric(self, labels, value, timestamp=None):
        """Add a metric to the metric family.
        Args:
        labels: A list of label values
        value: The value of the metric.
        """
        self.samples.append(Sample(self.name, dict(zip(self._labelnames, labels)), value, timestamp))


# For backward compatibility.
UntypedMetricFamily = UnknownMetricFamily


class CounterMetricFamily(Metric):
    """A single counter and its samples.

    For use by custom collectors.
    """

    def __init__(self, name, documentation, value=None, labels=None, created=None, unit=''):
        # Glue code for pre-OpenMetrics metrics.
        if name.endswith('_total'):
            name = name[:-6]
        Metric.__init__(self, name, documentation, 'counter', unit)
        if labels is not None and value is not None:
            raise ValueError('Can only specify at most one of value and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if value is not None:
            self.add_metric([], value, created)

    def add_metric(self, labels, value, created=None, timestamp=None):
        """Add a metric to the metric family.

        Args:
          labels: A list of label values
          value: The value of the metric
          created: Optional unix timestamp the child was created at.
        """
        self.samples.append(Sample(self.name + '_total', dict(zip(self._labelnames, labels)), value, timestamp))
        if created is not None:
            self.samples.append(Sample(self.name + '_created', dict(zip(self._labelnames, labels)), created, timestamp))


class GaugeMetricFamily(Metric):
    """A single gauge and its samples.

    For use by custom collectors.
    """

    def __init__(self, name, documentation, value=None, labels=None, unit=''):
        Metric.__init__(self, name, documentation, 'gauge', unit)
        if labels is not None and value is not None:
            raise ValueError('Can only specify at most one of value and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if value is not None:
            self.add_metric([], value)

    def add_metric(self, labels, value, timestamp=None):
        """Add a metric to the metric family.

        Args:
          labels: A list of label values
          value: A float
        """
        self.samples.append(Sample(self.name, dict(zip(self._labelnames, labels)), value, timestamp))


class SummaryMetricFamily(Metric):
    """A single summary and its samples.

    For use by custom collectors.
    """

    def __init__(self, name, documentation, count_value=None, sum_value=None, labels=None, unit=''):
        Metric.__init__(self, name, documentation, 'summary', unit)
        if (sum_value is None) != (count_value is None):
            raise ValueError('count_value and sum_value must be provided together.')
        if labels is not None and count_value is not None:
            raise ValueError('Can only specify at most one of value and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if count_value is not None:
            self.add_metric([], count_value, sum_value)

    def add_metric(self, labels, count_value, sum_value, timestamp=None):
        """Add a metric to the metric family.

        Args:
          labels: A list of label values
          count_value: The count value of the metric.
          sum_value: The sum value of the metric.
        """
        self.samples.append(Sample(self.name + '_count', dict(zip(self._labelnames, labels)), count_value, timestamp))
        self.samples.append(Sample(self.name + '_sum', dict(zip(self._labelnames, labels)), sum_value, timestamp))


class HistogramMetricFamily(Metric):
    """A single histogram and its samples.

    For use by custom collectors.
    """

    def __init__(self, name, documentation, buckets=None, sum_value=None, labels=None, unit=''):
        Metric.__init__(self, name, documentation, 'histogram', unit)
        if sum_value is not None and buckets is None:
            raise ValueError('sum value cannot be provided without buckets.')
        if labels is not None and buckets is not None:
            raise ValueError('Can only specify at most one of buckets and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if buckets is not None:
            self.add_metric([], buckets, sum_value)

    def add_metric(self, labels, buckets, sum_value, timestamp=None):
        """Add a metric to the metric family.

        Args:
          labels: A list of label values
          buckets: A list of lists.
              Each inner list can be a pair of bucket name and value,
              or a triple of bucket name, value, and exemplar.
              The buckets must be sorted, and +Inf present.
          sum_value: The sum value of the metric.
        """
        for b in buckets:
            bucket, value = b[:2]
            exemplar = None
            if len(b) == 3:
                exemplar = b[2]
            self.samples.append(Sample(
                self.name + '_bucket',
                dict(list(zip(self._labelnames, labels)) + [('le', bucket)]),
                value,
                timestamp,
                exemplar,
            ))
        # +Inf is last and provides the count value.
        self.samples.append(
                Sample(self.name + '_count', dict(zip(self._labelnames, labels)), buckets[-1][1], timestamp))
        # Don't iunclude sum if there's negative buckets.
        if float(buckets[0][0]) >= 0 and sum_value is not None:
            self.samples.append(
                    Sample(self.name + '_sum', dict(zip(self._labelnames, labels)), sum_value, timestamp))



class GaugeHistogramMetricFamily(Metric):
    """A single gauge histogram and its samples.

    For use by custom collectors.
    """

    def __init__(self, name, documentation, buckets=None, gsum_value=None, labels=None, unit=''):
        Metric.__init__(self, name, documentation, 'gaugehistogram', unit)
        if labels is not None and buckets is not None:
            raise ValueError('Can only specify at most one of buckets and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if buckets is not None:
            self.add_metric([], buckets, gsum_value)

    def add_metric(self, labels, buckets, gsum_value, timestamp=None):
        """Add a metric to the metric family.

        Args:
          labels: A list of label values
          buckets: A list of pairs of bucket names and values.
              The buckets must be sorted, and +Inf present.
          gsum_value: The sum value of the metric.
        """
        for bucket, value in buckets:
            self.samples.append(Sample(
                self.name + '_bucket',
                dict(list(zip(self._labelnames, labels)) + [('le', bucket)]),
                value, timestamp))
        # +Inf is last and provides the count value.
        self.samples.extend([
            Sample(self.name + '_gcount', dict(zip(self._labelnames, labels)), buckets[-1][1], timestamp),
            Sample(self.name + '_gsum', dict(zip(self._labelnames, labels)), gsum_value, timestamp),
        ])


class InfoMetricFamily(Metric):
    """A single info and its samples.

    For use by custom collectors.
    """

    def __init__(self, name, documentation, value=None, labels=None):
        Metric.__init__(self, name, documentation, 'info')
        if labels is not None and value is not None:
            raise ValueError('Can only specify at most one of value and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if value is not None:
            self.add_metric([], value)

    def add_metric(self, labels, value, timestamp=None):
        """Add a metric to the metric family.

        Args:
          labels: A list of label values
          value: A dict of labels
        """
        self.samples.append(Sample(
            self.name + '_info',
            dict(dict(zip(self._labelnames, labels)), **value),
            1,
            timestamp,
        ))


class StateSetMetricFamily(Metric):
    """A single stateset and its samples.

    For use by custom collectors.
    """

    def __init__(self, name, documentation, value=None, labels=None):
        Metric.__init__(self, name, documentation, 'stateset')
        if labels is not None and value is not None:
            raise ValueError('Can only specify at most one of value and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if value is not None:
            self.add_metric([], value)

    def add_metric(self, labels, value, timestamp=None):
        """Add a metric to the metric family.

        Args:
          labels: A list of label values
          value: A dict of string state names to booleans
        """
        labels = tuple(labels)
        for state, enabled in sorted(value.items()):
            v = (1 if enabled else 0)
            self.samples.append(Sample(
                self.name,
                dict(zip(self._labelnames + (self.name,), labels + (state,))),
                v,
                timestamp,
            ))
