# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

from docutils import nodes

from sphinx.util.compat import Directive, make_admonition


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

        ad = make_admonition(
            Hazmat,
            self.name,
            [],
            self.options,
            nodes.paragraph("", message),
            self.lineno,
            self.content_offset,
            self.block_text,
            self.state,
            self.state_machine
        )
        ad[0].line = self.lineno
        return ad


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
