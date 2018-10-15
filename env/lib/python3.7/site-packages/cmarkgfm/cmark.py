"""Python bindings to GitHub's cmark Markdown library."""

from __future__ import unicode_literals

from cmarkgfm import _cmark


class Options(object):
    CMARK_OPT_DEFAULT = _cmark.lib.CMARK_OPT_DEFAULT
    CMARK_OPT_SOURCEPOS = _cmark.lib.CMARK_OPT_SOURCEPOS
    CMARK_OPT_HARDBREAKS = _cmark.lib.CMARK_OPT_HARDBREAKS
    CMARK_OPT_SAFE = _cmark.lib.CMARK_OPT_SAFE
    CMARK_OPT_NOBREAKS = _cmark.lib.CMARK_OPT_NOBREAKS
    CMARK_OPT_NORMALIZE = _cmark.lib.CMARK_OPT_NORMALIZE
    CMARK_OPT_VALIDATE_UTF8 = _cmark.lib.CMARK_OPT_VALIDATE_UTF8
    CMARK_OPT_SMART = _cmark.lib.CMARK_OPT_SMART
    CMARK_OPT_GITHUB_PRE_LANG = _cmark.lib.CMARK_OPT_GITHUB_PRE_LANG
    CMARK_OPT_LIBERAL_HTML_TAG = _cmark.lib.CMARK_OPT_LIBERAL_HTML_TAG
    CMARK_OPT_FOOTNOTES = _cmark.lib.CMARK_OPT_FOOTNOTES
    CMARK_OPT_STRIKETHROUGH_DOUBLE_TILDE = (
        _cmark.lib.CMARK_OPT_STRIKETHROUGH_DOUBLE_TILDE)
    CMARK_OPT_TABLE_PREFER_STYLE_ATTRIBUTES = (
        _cmark.lib.CMARK_OPT_TABLE_PREFER_STYLE_ATTRIBUTES)


def markdown_to_html(text, options=0):
    """Render the given text to Markdown.

    This is a direct interface to ``cmark_markdown_to_html``.

    Args:
        text (str): The text to render to Markdown.
        options (int): The cmark options.

    Returns:
        str: The rendered markdown.
    """
    encoded_text = text.encode('utf-8')
    raw_result = _cmark.lib.cmark_markdown_to_html(
        encoded_text, len(encoded_text), options)
    return _cmark.ffi.string(raw_result).decode('utf-8')


def markdown_to_html_with_extensions(text, options=0, extensions=None):
    """Render the given text to Markdown, using extensions.

    This is a high-level wrapper over the various functions needed to enable
    extensions, attach them to a parser, and render html.

    Args:
        text (str): The text to render to Markdown.
        options (int): The cmark options.
        extensions (Sequence[str]): The list of extension names to use.

    Returns:
        str: The rendered markdown.
    """
    if extensions is None:
        extensions = []

    core_extensions_ensure_registered()

    cmark_extensions = []
    for extension_name in extensions:
        extension = find_syntax_extension(extension_name)
        if extension is None:
            raise ValueError('Unknown extension {}'.format(extension_name))
        cmark_extensions.append(extension)

    parser = parser_new(options=options)

    try:
        for extension in cmark_extensions:
            parser_attach_syntax_extension(parser, extension)

        parser_feed(parser, text)

        root = parser_finish(parser)

        if _cmark.lib.cmark_node_get_type(root) == _cmark.lib.CMARK_NODE_NONE:
            raise ValueError('Error parsing markdown!')

        extensions_ll = parser_get_syntax_extensions(parser)

        output = render_html(root, options=options, extensions=extensions_ll)

    finally:
        parser_free(parser)

    return output


def github_flavored_markdown_to_html(text, options=0):
    """Render the given GitHub-flavored Makrdown to HTML.

    This is a small wrapper over :func:`markdown_to_html_with_extensions` that
    just applies GitHub's extensions.

    Args:
        text (str): The text to render to Markdown.
        options (int): The cmark options.

    Returns:
        str: The rendered markdown.
    """
    return markdown_to_html_with_extensions(
        text, options=options,
        extensions=['table', 'autolink', 'tagfilter', 'strikethrough'])


def parse_document(text, options=0):
    """Parse a document and return the root node.

    Args:
        text (str): The text to parse.
        options (int): The cmark options.

    Returns:
        Any: Opaque reference to the root node of the parsed syntax tree.
    """
    encoded_text = text.encode('utf-8')
    return _cmark.lib.cmark_parse_document(
        encoded_text, len(encoded_text), options)


def parser_new(options=0):
    """Direct wrapper over cmark_parser_new."""
    return _cmark.lib.cmark_parser_new(options)


def parser_free(parser):
    """Direct wrapper over cmark_parser_free."""
    return _cmark.lib.cmark_parser_free(parser)


def parser_feed(parser, text):
    """Direct wrapper over cmark_parser_feed."""
    encoded_text = text.encode('utf-8')
    return _cmark.lib.cmark_parser_feed(
        parser, encoded_text, len(encoded_text))


def parser_finish(parser):
    """Direct wrapper over cmark_parser_finish."""
    return _cmark.lib.cmark_parser_finish(parser)


def render_html(root, options=0, extensions=None):
    """Render a given syntax tree as HTML.

    Args:
        root (Any): The reference to the root node of the syntax tree.
        options (int): The cmark options.
        extensions (Any): The reference to the syntax extensions, generally
            from :func:`parser_get_syntax_extensions`

    Returns:
        str: The rendered HTML.
    """
    if extensions is None:
        extensions = _cmark.ffi.NULL

    raw_result = _cmark.lib.cmark_render_html(
        root, options, extensions)

    return _cmark.ffi.string(raw_result).decode('utf-8')


def core_extensions_ensure_registered():
    """Direct wrapper over core_extensions_ensure_registered."""
    _cmark.lib.core_extensions_ensure_registered()


def find_syntax_extension(name):
    """Direct wrapper over cmark_find_syntax_extension."""
    encoded_name = name.encode('utf-8')
    extension = _cmark.lib.cmark_find_syntax_extension(encoded_name)

    if extension == _cmark.ffi.NULL:
        return None
    else:
        return extension


def parser_attach_syntax_extension(parser, extension):
    """Direct wrapper over cmark_parser_attach_syntax_extension."""
    _cmark.lib.cmark_parser_attach_syntax_extension(parser, extension)


def parser_get_syntax_extensions(parser):
    """Direct wrapper over cmark_parser_get_syntax_extensions."""
    return _cmark.lib.cmark_parser_get_syntax_extensions(parser)
