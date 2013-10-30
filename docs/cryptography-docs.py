from docutils import nodes

from sphinx.util.compat import Directive, make_admonition


DANGER_MESSAGE = """
This is a "Hazardous Materials" module. You should **ONLY** use it if you're
100% absolutely sure that you know what you're doing because this module is
full of land mines, dragons, and dinosaurs with laser guns. """


class HazmatDirective(Directive):
    def run(self):
        ad = make_admonition(
            Hazmat,
            self.name,
            [],
            self.options,
            nodes.paragraph("", DANGER_MESSAGE),
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


def visit_hazmat_node(self, node):
    return self.visit_admonition(node, "danger")


def depart_hazmat_node(self, node):
    return self.depart_admonition(node)


def setup(app):
    app.add_node(
        Hazmat,
        html=(visit_hazmat_node, depart_hazmat_node)
    )
    app.add_directive("hazmat", HazmatDirective)
