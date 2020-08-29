# -*- coding: utf-8 -*-
"""HTML Exporter class"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import os

from traitlets import default, Unicode
from traitlets.config import Config
from jupyter_core.paths import jupyter_path
from jinja2 import contextfilter

from nbconvert.filters.highlight import Highlight2HTML
from nbconvert.filters.markdown_mistune import IPythonRenderer, MarkdownWithMath

from .templateexporter import TemplateExporter


class HTMLExporter(TemplateExporter):
    """
    Exports a basic HTML document.  This exporter assists with the export of
    HTML.  Inherit from it if you are writing your own HTML template and need
    custom preprocessors/filters.  If you don't need custom preprocessors/
    filters, just change the 'template_file' config option.
    """
    export_from_notebook = "HTML"

    anchor_link_text = Unicode(u'¶',
        help="The text used as the text for anchor links.").tag(config=True)

    @default('file_extension')
    def _file_extension_default(self):
        return '.html'

    @default('default_template_path')
    def _default_template_path_default(self):
        return os.path.join("..", "templates", "html")

    @default('template_data_paths')
    def _template_data_paths_default(self):
        return jupyter_path("nbconvert", "templates", "html")

    @default('template_file')
    def _template_file_default(self):
        return 'full.tpl'

    output_mimetype = 'text/html'

    @property
    def default_config(self):
        c = Config({
            'NbConvertBase': {
                'display_data_priority' : ['application/vnd.jupyter.widget-state+json',
                                           'application/vnd.jupyter.widget-view+json',
                                           'application/javascript',
                                           'text/html',
                                           'text/markdown',
                                           'image/svg+xml',
                                           'text/latex',
                                           'image/png',
                                           'image/jpeg',
                                           'text/plain'
                                          ]
                },
            'CSSHTMLHeaderPreprocessor':{
                'enabled':True
                },
            'HighlightMagicsPreprocessor': {
                'enabled':True
                }
            })
        c.merge(super(HTMLExporter,self).default_config)
        return c

    @contextfilter
    def markdown2html(self, context, source):
        """Markdown to HTML filter respecting the anchor_link_text setting"""
        cell = context.get('cell', {})
        attachments = cell.get('attachments', {})
        renderer = IPythonRenderer(escape=False, attachments=attachments,
                                   anchor_link_text=self.anchor_link_text)
        return MarkdownWithMath(renderer=renderer).render(source)

    def default_filters(self):
        for pair in super(HTMLExporter, self).default_filters():
            yield pair
        yield ('markdown2html', self.markdown2html)

    def from_notebook_node(self, nb, resources=None, **kw):
        langinfo = nb.metadata.get('language_info', {})
        lexer = langinfo.get('pygments_lexer', langinfo.get('name', None))
        highlight_code = self.filters.get('highlight_code', Highlight2HTML(pygments_lexer=lexer, parent=self))
        self.register_filter('highlight_code', highlight_code)
        return super(HTMLExporter, self).from_notebook_node(nb, resources, **kw)
