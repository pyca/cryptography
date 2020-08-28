"""Code for supporting compatibility across python versions."""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

try:
    from base64 import decodebytes, encodebytes
except ImportError:
    from base64 import encodestring as encodebytes
    from base64 import decodestring as decodebytes
