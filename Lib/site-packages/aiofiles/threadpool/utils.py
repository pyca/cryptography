import functools
from types import coroutine


def delegate_to_executor(*attrs):
    def cls_builder(cls):
        for attr_name in attrs:
            setattr(cls, attr_name, _make_delegate_method(attr_name))
        return cls

    return cls_builder


def proxy_method_directly(*attrs):
    def cls_builder(cls):
        for attr_name in attrs:
            setattr(cls, attr_name, _make_proxy_method(attr_name))
        return cls

    return cls_builder


def proxy_property_directly(*attrs):
    def cls_builder(cls):
        for attr_name in attrs:
            setattr(cls, attr_name, _make_proxy_property(attr_name))
        return cls

    return cls_builder


def _make_delegate_method(attr_name):
    @coroutine
    def method(self, *args, **kwargs):
        cb = functools.partial(getattr(self._file, attr_name), *args, **kwargs)
        return (yield from self._loop.run_in_executor(self._executor, cb))

    return method


def _make_proxy_method(attr_name):
    def method(self, *args, **kwargs):
        return getattr(self._file, attr_name)(*args, **kwargs)

    return method


def _make_proxy_property(attr_name):
    def proxy_property(self):
        return getattr(self._file, attr_name)

    return property(proxy_property)
