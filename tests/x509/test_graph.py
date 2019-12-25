# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest
from cryptography.x509.graph import Graph


def graph_from_edges(edges):
    """ 'edges' is an array of two-letter strings, just to save typing """
    g = Graph()
    for e in edges:
        src = e[0]
        dst = e[1]
        try:
            g.add_vertex(src)
        except KeyError:
            pass
        try:
            g.add_vertex(dst)
        except KeyError:
            pass
        try:
            g.add_edge(src, dst)
        except KeyError:
            pass
    return g


class TestGraphs(object):
    def test_graph_with_cycles(self):
        """ Random simple graph, with cycles though """
        g1 = graph_from_edges(['AB', 'AC', 'BC', 'BD', 'CD', 'DC', 'EF', 'FC'])
        assert g1.all_paths('A', 'D') == [['A', 'B', 'C', 'D'], ['A', 'B', 'D'], ['A', 'C', 'D']]
        assert g1.all_paths('A', 'E') == []

    def test_too_long_path_cutout(self):
        """ Fail whenever path longer than Graph.MAX_PATH_LENGTH is encountered """
        twelve_vertices = 'ABCDEFGHIJKL'
        complete_graph_12 = Graph()
        for v in twelve_vertices:
            complete_graph_12.add_vertex(v)
        for src in twelve_vertices:
            for dst in twelve_vertices:
                complete_graph_12.add_edge(src, dst)

        with pytest.raises(RecursionError):
            complete_graph_12.all_paths('A', 'B')
