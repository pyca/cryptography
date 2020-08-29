"""
Python-Markdown Markdown in HTML Extension
===============================

An implementation of [PHP Markdown Extra](http://michelf.com/projects/php-markdown/extra/)'s
parsing of Markdown syntax in raw HTML.

See <https://Python-Markdown.github.io/extensions/raw_html>
for documentation.

Copyright The Python Markdown Project

License: [BSD](https://opensource.org/licenses/bsd-license.php)

"""

from . import Extension
from ..blockprocessors import BlockProcessor
from .. import util
import re
import xml.etree.ElementTree as etree


class MarkdownInHtmlProcessor(BlockProcessor):
    """Process Markdown Inside HTML Blocks."""
    def test(self, parent, block):
        return block == util.TAG_PLACEHOLDER % \
            str(self.parser.blockprocessors.tag_counter + 1)

    def _process_nests(self, element, block):
        """Process the element's child elements in self.run."""
        # Build list of indexes of each nest within the parent element.
        nest_index = []  # a list of tuples: (left index, right index)
        i = self.parser.blockprocessors.tag_counter + 1
        while len(self._tag_data) > i and self._tag_data[i]['left_index']:
            left_child_index = self._tag_data[i]['left_index']
            right_child_index = self._tag_data[i]['right_index']
            nest_index.append((left_child_index - 1, right_child_index))
            i += 1

        # Create each nest subelement.
        for i, (left_index, right_index) in enumerate(nest_index[:-1]):
            self.run(element, block[left_index:right_index],
                     block[right_index:nest_index[i + 1][0]], True)
        self.run(element, block[nest_index[-1][0]:nest_index[-1][1]],  # last
                 block[nest_index[-1][1]:], True)                      # nest

    def run(self, parent, blocks, tail=None, nest=False):
        self._tag_data = self.parser.md.htmlStash.tag_data

        self.parser.blockprocessors.tag_counter += 1
        tag = self._tag_data[self.parser.blockprocessors.tag_counter]

        # Create Element
        markdown_value = tag['attrs'].pop('markdown')
        element = etree.SubElement(parent, tag['tag'], tag['attrs'])

        # Slice Off Block
        if nest:
            self.parser.parseBlocks(parent, tail)  # Process Tail
            block = blocks[1:]
        else:  # includes nests since a third level of nesting isn't supported
            block = blocks[tag['left_index'] + 1: tag['right_index']]
            del blocks[:tag['right_index']]

        # Process Text
        if (self.parser.blockprocessors.contain_span_tags.match(  # Span Mode
                tag['tag']) and markdown_value != 'block') or \
                markdown_value == 'span':
            element.text = '\n'.join(block)
        else:                                                     # Block Mode
            i = self.parser.blockprocessors.tag_counter + 1
            if len(self._tag_data) > i and self._tag_data[i]['left_index']:
                first_subelement_index = self._tag_data[i]['left_index'] - 1
                self.parser.parseBlocks(
                    element, block[:first_subelement_index])
                if not nest:
                    block = self._process_nests(element, block)
            else:
                self.parser.parseBlocks(element, block)


class MarkdownInHtmlExtension(Extension):
    """Add Markdown parsing in HTML to Markdown class."""

    def extendMarkdown(self, md):
        """ Register extension instances. """

        # Turn on processing of markdown text within raw html
        md.preprocessors['html_block'].markdown_in_raw = True
        md.parser.blockprocessors.register(
            MarkdownInHtmlProcessor(md.parser), 'markdown_block', 105
        )
        md.parser.blockprocessors.tag_counter = -1
        md.parser.blockprocessors.contain_span_tags = re.compile(
            r'^(p|h[1-6]|li|dd|dt|td|th|legend|address)$', re.IGNORECASE)


def makeExtension(**kwargs):  # pragma: no cover
    return MarkdownInHtmlExtension(**kwargs)
