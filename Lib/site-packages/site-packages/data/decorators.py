from decorator import FunctionMaker
from six import PY2, wraps
if PY2:
    from funcsigs import signature, _empty
else:
    from inspect import signature, _empty

from . import Data


def annotate(*args, **kwargs):
    """Set function annotations (on Python2 and 3)."""
    def decorator(f):
        if not hasattr(f, '__annotations__'):
            f.__annotations__ = kwargs.copy()
        else:
            f.__annotations__.update(kwargs)

        if args:
            if len(args) != 1:
                raise ValueError('annotate supports only a single argument.')
            f.__annotations__['return'] = args[0]
        return f

    return decorator


def auto_instantiate(*classes):
    """Creates a decorator that will instantiate objects based on function
    parameter annotations.

    The decorator will check every argument passed into ``f``. If ``f`` has an
    annotation for the specified parameter and the annotation is found in
    ``classes``, the parameter value passed in will be used to construct a new
    instance of the expression that is the annotation.

    An example (Python 3):

    .. code-block:: python

        @auto_instantiate(int)
        def foo(a: int, b: float):
            pass

    Any value passed in as ``b`` is left unchanged. Anything passed as the
    parameter for ``a`` will be converted to :class:`int` before calling the
    function.

    Since Python 2 does not support annotations, the
    :func:`~data.decorators.annotate` function should can be used:

    .. code-block:: python

        @auto_instantiate(int)
        @annotate(a=int)
        def foo(a, b):
            pass


    :param classes: Any number of classes/callables for which
                    auto-instantiation should be performed. If empty, perform
                    for all.

    :note: When dealing with data, it is almost always more convenient to use
           the :func:`~data.decorators.data` decorator instead.
    """
    def decorator(f):
        # collect our argspec
        sig = signature(f)

        @wraps(f)
        def _(*args, **kwargs):
            bvals = sig.bind(*args, **kwargs)

            # replace with instance if desired
            for varname, val in bvals.arguments.items():
                anno = sig.parameters[varname].annotation

                if anno in classes or (len(classes) == 0 and anno != _empty):
                    bvals.arguments[varname] = anno(val)

            return f(*bvals.args, **bvals.kwargs)

        # create another layer by wrapping in a FunctionMaker. this is done
        # to preserve the original signature
        return FunctionMaker.create(
            f, 'return _(%(signature)s)', dict(_=_, __wrapped__=f)
        )

    return decorator


def data(*argnames):
    """Designate an argument as a :class:`~data.Data` argument.

    Works by combining calls to :func:`~data.decorators.auto_instantiate` and
    :func:~data.decorators.annotate` on the named arguments.

    Example:

    .. code-block:: python

       class Foo(object):
           @data('bar')
           def meth(self, foo, bar):
               pass

    Inside ``meth``, ``bar`` will always be a :class:`~data.Data` instance
    constructed from the original value passed as ``bar``.

    :param argnames: List of parameter names that should be data arguments.
    :return: A decorator that converts the named arguments to
             :class:`~data.Data` instances."""
    # make it work if given only one argument (for Python3)
    if len(argnames) == 1 and callable(argnames[0]):
        return data()(argnames[0])

    def decorator(f):
        f = annotate(**dict((argname, Data) for argname in argnames))(f)
        f = auto_instantiate(Data)(f)
        return f
    return decorator


def file_arg(argname, file_arg_suffix='_file'):
    # this function is currently undocumented, as it's likely to be deemed a
    # bad idea and be removed later
    file_arg_name = argname + file_arg_suffix

    def decorator(f):
        sig = signature(f)

        if file_arg_name in sig.parameters:
            raise ValueError('{} already has a parameter named {}'
                             .format(f, file_arg_name))

        @wraps(f)
        def _(*args, **kwargs):
            # remove file_arg_name from function list
            a_file = kwargs.pop(file_arg_name, None)

            # bind remaining arguments
            pbargs = sig.bind_partial(*args, **kwargs)

            # get data argument
            a_data = pbargs.arguments.get(argname, None)

            # if a Data object is already being passed in, use it
            # instead of creating a new instance
            if a_file is None and isinstance(a_data, Data):
                d = a_data
            else:
                # create data replacement
                d = Data(data=a_data, file=a_file)

            # replace with data instance
            pbargs.parameters[argname] = d

            # call original function with instantiated data argument
            return f(*pbargs.args, **pbargs.kwargs)
        return _
    return decorator
