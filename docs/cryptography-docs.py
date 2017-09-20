# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from docutils import nodes

from sphinx.util.compat import Directive


DANGER_MESSAGE = """
This is a "Hazardous Materials" module. You should **ONLY** use it if you're
100% absolutely sure that you know what you're doing because this module is
full of land mines, dragons, and dinosaurs with laser guns.
"""

DANGER_ALTERNATE = """

You may instead be interested in :doc:`{alternate}`.
"""


class HazmatDirective(Directive):
    has_content = True

    def run(self):
        message = DANGER_MESSAGE
        if self.content:
            message += DANGER_ALTERNATE.format(alternate=self.content[0])

        content = nodes.paragraph("", message)
        admonition_node = Hazmat("\n".join(content))
        self.state.nested_parse(content, self.content_offset, admonition_node)
        admonition_node.line = self.lineno
        return [admonition_node]


class Hazmat(nodes.Admonition, nodes.Element):
    pass


def html_visit_hazmat_node(self, node):
    return self.visit_admonition(node, "danger")


def latex_visit_hazmat_node(self, node):
    return self.visit_admonition(node)


def depart_hazmat_node(self, node):
    return self.depart_admonition(node)


def setup(app):
    app.add_node(
        Hazmat,
        html=(html_visit_hazmat_node, depart_hazmat_node),
        latex=(latex_visit_hazmat_node, depart_hazmat_node),
    )
    app.add_directive("hazmat", HazmatDirective)

    return {
        "parallel_read_safe": True,
    }
