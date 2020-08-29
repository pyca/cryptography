"""
`parse_bits` is copied from Django 1.8 `django.template.base.parse_bits`.

Copyright (c) Django Software Foundation and individual contributors.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    3. Neither the name of Django nor the names of its contributors may be used
       to endorse or promote products derived from this software without
       specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from django.template.base import TemplateSyntaxError, token_kwargs
from django.utils import six

def parse_bits(parser, bits, params, varargs, varkw, defaults,
               takes_context, name):
    """
    Parses bits for template tag helpers (simple_tag, include_tag and
    assignment_tag), in particular by detecting syntax errors and by
    extracting positional and keyword arguments.
    """
    if takes_context:
        if params[0] == 'context':
            params = params[1:]
        else:
            raise TemplateSyntaxError(
                "'%s' is decorated with takes_context=True so it must "
                "have a first argument of 'context'" % name)
    args = []
    kwargs = {}
    unhandled_params = list(params)
    for bit in bits:
        # First we try to extract a potential kwarg from the bit
        kwarg = token_kwargs([bit], parser)
        if kwarg:
            # The kwarg was successfully extracted
            param, value = list(six.iteritems(kwarg))[0]
            if param not in params and varkw is None:
                # An unexpected keyword argument was supplied
                raise TemplateSyntaxError(
                    "'%s' received unexpected keyword argument '%s'" %
                    (name, param))
            elif param in kwargs:
                # The keyword argument has already been supplied once
                raise TemplateSyntaxError(
                    "'%s' received multiple values for keyword argument '%s'" %
                    (name, param))
            else:
                # All good, record the keyword argument
                kwargs[str(param)] = value
                if param in unhandled_params:
                    # If using the keyword syntax for a positional arg, then
                    # consume it.
                    unhandled_params.remove(param)
        else:
            if kwargs:
                raise TemplateSyntaxError(
                    "'%s' received some positional argument(s) after some "
                    "keyword argument(s)" % name)
            else:
                # Record the positional argument
                args.append(parser.compile_filter(bit))
                try:
                    # Consume from the list of expected positional arguments
                    unhandled_params.pop(0)
                except IndexError:
                    if varargs is None:
                        raise TemplateSyntaxError(
                            "'%s' received too many positional arguments" %
                            name)
    if defaults is not None:
        # Consider the last n params handled, where n is the
        # number of defaults.
        unhandled_params = unhandled_params[:-len(defaults)]
    if unhandled_params:
        # Some positional arguments were not supplied
        raise TemplateSyntaxError(
            "'%s' did not receive value(s) for the argument(s): %s" %
            (name, ", ".join("'%s'" % p for p in unhandled_params)))
    return args, kwargs
