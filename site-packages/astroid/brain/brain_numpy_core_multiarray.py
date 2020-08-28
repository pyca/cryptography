# Copyright (c) 2019-2020 hippo91 <guillaume.peillex@gmail.com>

# Licensed under the LGPL: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html
# For details: https://github.com/PyCQA/astroid/blob/master/COPYING.LESSER


"""Astroid hooks for numpy.core.multiarray module."""

import functools
import astroid
from brain_numpy_utils import looks_like_numpy_member, infer_numpy_member


def numpy_core_multiarray_transform():
    return astroid.parse(
        """
    # different functions defined in multiarray.py
    def inner(a, b):
        return numpy.ndarray([0, 0])

    def vdot(a, b):
        return numpy.ndarray([0, 0])
        """
    )


astroid.register_module_extender(
    astroid.MANAGER, "numpy.core.multiarray", numpy_core_multiarray_transform
)


METHODS_TO_BE_INFERRED = {
    "array": """def array(object, dtype=None, copy=True, order='K', subok=False, ndmin=0):
            return numpy.ndarray([0, 0])""",
    "dot": """def dot(a, b, out=None):
            return numpy.ndarray([0, 0])""",
    "empty_like": """def empty_like(a, dtype=None, order='K', subok=True):
            return numpy.ndarray((0, 0))""",
    "concatenate": """def concatenate(arrays, axis=None, out=None):
            return numpy.ndarray((0, 0))""",
    "where": """def where(condition, x=None, y=None):
            return numpy.ndarray([0, 0])""",
    "empty": """def empty(shape, dtype=float, order='C'):
            return numpy.ndarray([0, 0])""",
    "bincount": """def bincount(x, weights=None, minlength=0):
            return numpy.ndarray([0, 0])""",
    "busday_count": """def busday_count(begindates, enddates, weekmask='1111100', holidays=[], busdaycal=None, out=None):
            return numpy.ndarray([0, 0])""",
    "busday_offset": """def busday_offset(dates, offsets, roll='raise', weekmask='1111100', holidays=None, busdaycal=None, out=None):
            return numpy.ndarray([0, 0])""",
    "can_cast": """def can_cast(from_, to, casting='safe'):
            return True""",
    "copyto": """def copyto(dst, src, casting='same_kind', where=True):
            return None""",
    "datetime_as_string": """def datetime_as_string(arr, unit=None, timezone='naive', casting='same_kind'):
            return numpy.ndarray([0, 0])""",
    "is_busday": """def is_busday(dates, weekmask='1111100', holidays=None, busdaycal=None, out=None):
            return numpy.ndarray([0, 0])""",
    "lexsort": """def lexsort(keys, axis=-1):
            return numpy.ndarray([0, 0])""",
    "may_share_memory": """def may_share_memory(a, b, max_work=None):
            return True""",
    # Not yet available because dtype is not yet present in those brains
    #     "min_scalar_type": """def min_scalar_type(a):
    #             return numpy.dtype('int16')""",
    "packbits": """def packbits(a, axis=None, bitorder='big'):
            return numpy.ndarray([0, 0])""",
    # Not yet available because dtype is not yet present in those brains
    #     "result_type": """def result_type(*arrays_and_dtypes):
    #             return numpy.dtype('int16')""",
    "shares_memory": """def shares_memory(a, b, max_work=None):
            return True""",
    "unpackbits": """def unpackbits(a, axis=None, count=None, bitorder='big'):
            return numpy.ndarray([0, 0])""",
    "unravel_index": """def unravel_index(indices, shape, order='C'):
            return (numpy.ndarray([0, 0]),)""",
    "zeros": """def zeros(shape, dtype=float, order='C'):
            return numpy.ndarray([0, 0])""",
}

for method_name, function_src in METHODS_TO_BE_INFERRED.items():
    inference_function = functools.partial(infer_numpy_member, function_src)
    astroid.MANAGER.register_transform(
        astroid.Attribute,
        astroid.inference_tip(inference_function),
        functools.partial(looks_like_numpy_member, method_name),
    )
    astroid.MANAGER.register_transform(
        astroid.Name,
        astroid.inference_tip(inference_function),
        functools.partial(looks_like_numpy_member, method_name),
    )
