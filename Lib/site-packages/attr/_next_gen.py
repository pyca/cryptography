"""
This is a Python 3.6 and later-only, keyword-only, and **provisional** API that
calls `attr.s` with different default values.

Provisional APIs that shall become "import attrs" one glorious day.
"""

from functools import partial

from attr.exceptions import UnannotatedAttributeError

from . import setters
from ._make import NOTHING, attrib, attrs


def define(
    maybe_cls=None,
    *,
    these=None,
    repr=None,
    hash=None,
    init=None,
    slots=True,
    frozen=False,
    weakref_slot=True,
    str=False,
    auto_attribs=None,
    kw_only=False,
    cache_hash=False,
    auto_exc=True,
    eq=True,
    order=False,
    auto_detect=True,
    getstate_setstate=None,
    on_setattr=setters.validate,
):
    r"""
    The only behavioral difference is the handling of the *auto_attribs*
    option:

    :param Optional[bool] auto_attribs: If set to `True` or `False`, it behaves
       exactly like `attr.s`. If left `None`, `attr.s` will try to guess:

       1. If all attributes are annotated and no `attr.ib` is found, it assumes
          *auto_attribs=True*.
       2. Otherwise it assumes *auto_attribs=False* and tries to collect
          `attr.ib`\ s.


    .. versionadded:: 20.1.0
    """

    def do_it(auto_attribs):
        return attrs(
            maybe_cls=maybe_cls,
            these=these,
            repr=repr,
            hash=hash,
            init=init,
            slots=slots,
            frozen=frozen,
            weakref_slot=weakref_slot,
            str=str,
            auto_attribs=auto_attribs,
            kw_only=kw_only,
            cache_hash=cache_hash,
            auto_exc=auto_exc,
            eq=eq,
            order=order,
            auto_detect=auto_detect,
            collect_by_mro=True,
            getstate_setstate=getstate_setstate,
            on_setattr=on_setattr,
        )

    if auto_attribs is not None:
        return do_it(auto_attribs)

    try:
        return do_it(True)
    except UnannotatedAttributeError:
        return do_it(False)


mutable = define
frozen = partial(define, frozen=True, on_setattr=None)


def field(
    *,
    default=NOTHING,
    validator=None,
    repr=True,
    hash=None,
    init=True,
    metadata=None,
    converter=None,
    factory=None,
    kw_only=False,
    eq=None,
    order=None,
    on_setattr=None,
):
    """
    Identical to `attr.ib`, except keyword-only and with some arguments
    removed.

    .. versionadded:: 20.1.0
    """
    return attrib(
        default=default,
        validator=validator,
        repr=repr,
        hash=hash,
        init=init,
        metadata=metadata,
        converter=converter,
        factory=factory,
        kw_only=kw_only,
        eq=eq,
        order=order,
        on_setattr=on_setattr,
    )
