import functools
import sys


PY3K = sys.version_info >= (3,)


methods = set([
    "__iter__",
    "__len__",
    "__contains__",
    "__getitem__",
    "__setitem__",
    "__delitem__",

    "__enter__",
    "__exit__",

    "__lt__",
    "__le__",
    "__eq__",
    "__ne__",
    "__gt__",
    "__ge__",

    "__add__",
    "__and__",
    "__divmod__",
    "__floordiv__",
    "__lshift__",
    "__mod__",
    "__mul__",
    "__or__",
    "__pow__",
    "__rshift__",
    "__sub__",
    "__truediv__",
    "__xor__",

    "__call__",
    "__repr__",
])
if PY3K:
    methods.add("__next__")
    methods.add("__bool__")
else:
    methods.add("__div__")
    methods.add("__nonzero__")
MAGIC_METHODS = frozenset(methods)
del methods


def _build_magic_dispatcher(method):
    def inner(self, *args, **kwargs):
        return self.__dict__[method](*args, **kwargs)
    inner.__name__ = method
    return inner


class stub(object):
    _classes_cache = {}

    def __new__(cls, **kwargs):
        magic_methods_present = MAGIC_METHODS.intersection(kwargs)
        if magic_methods_present not in cls._classes_cache:
            attrs = dict(
                (method, _build_magic_dispatcher(method))
                for method in magic_methods_present
            )
            attrs["__module__"] = cls.__module__
            cls._classes_cache[magic_methods_present] = (
                type("stub", (cls,), attrs)
            )
        new_cls = cls._classes_cache[magic_methods_present]
        return super(stub, new_cls).__new__(new_cls)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<stub(%s)>' % ', '.join([
            '%s=%r' % (key, val)
            for key, val in self.__dict__.items()
        ])


def raiser(exc):
    if (
        not (
            isinstance(exc, BaseException) or
            isinstance(exc, type) and issubclass(exc, BaseException)
        )
    ):
        raise TypeError("exc must be either an exception instance or class.")

    def inner(*args, **kwargs):
        raise exc
    return inner


class call(object):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __eq__(self, other):
        if not isinstance(other, call):
            return NotImplemented
        return self.args == other.args and self.kwargs == other.kwargs

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((
            self.args,
            frozenset(self.kwargs.items())
        ))

    def __repr__(self):
        args = ", ".join(map(repr, self.args))
        kwargs = ", ".join("%s=%r" % (k, v) for k, v in self.kwargs.items())
        comma = ", " if args and kwargs else ""
        return "<call(%s%s%s)>" % (args, comma, kwargs)


def call_recorder(func):
    @functools.wraps(func)
    def inner(*args, **kwargs):
        inner.calls.append(call(*args, **kwargs))
        return func(*args, **kwargs)
    inner.calls = []
    return inner
