from __future__ import absolute_import

from markupsafe import Markup
from jinja2 import Environment

from . import escape


class LatexMarkup(Markup):
    def unescape(self):
        raise NotImplementedError

    def stripstags(self):
        raise NotImplementedError

    @classmethod
    def escape(cls, s):
        if hasattr(s, '__html__'):
            return s.__html__()

        rv = escape(s)
        if rv.__class__ is not cls:
            return cls(rv)
        return rv


ENV_ARGS = {
    'block_start_string': '\BLOCK{',
    'block_end_string': '}',
    'variable_start_string': '\VAR{',
    'variable_end_string': '}',
    'comment_start_string': '\#{',
    'comment_end_string': '}',
    'line_statement_prefix': '%-',
    'line_comment_prefix': '%#',
    'trim_blocks': True,
    'autoescape': False,
}


def make_env(*args, **kwargs):
    """Creates an :py:class:`~jinja2.Environment` with different defaults.

    Per default, ``autoescape`` will be disabled and ``trim_blocks`` enabled.
    All start/end/prefix strings will be changed for a more LaTeX-friendly
    version (see the docs for details).

    Any arguments will be passed on to the :py:class:`~jinja2.Environment`
    constructor and override new values.

    Finally, the ``|e``, ``|escape`` and ``|forceescape`` filters will be
    replaced with a call to :func:`latex.escape`."""
    ka = ENV_ARGS.copy()
    ka.update(kwargs)

    env = Environment(*args, **ka)
    env.filters['e'] = LatexMarkup.escape
    env.filters['escape'] = LatexMarkup.escape
    env.filters['forceescape'] = LatexMarkup.escape  # FIXME: this is a bug
    return env
