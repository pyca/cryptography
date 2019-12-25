# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


class Graph(object):
    """
    Directed graph stored as adjacency list.

    Only parts necessary for building X.509 verification path are implemented.
    """

    # Algorithm to find all paths is exponential in number of vertices.
    # We need to refuse processing too large input in order to mitigate DoS
    # attacks, but the set of vertices contains trusted roots, which can
    # legitimately be large (hundreds).
    # Instead stop processing at given path length.
    MAX_PATH_LENGTH = 10

    def __init__(self):
        """ Initialize empty graph  """
        self.g = {}

    def add_vertex(self, vertex):
        """ Add a new vertex with no adjacent edges """
        if vertex in self.g:
            raise KeyError
        self.g[vertex] = []

    def add_edge(self, src, dst):
        """ Add edge src->dst. There can be at most one such. """
        if src not in self.g or dst not in self.g:
            raise KeyError
        if dst in self.g[src]:
            raise KeyError
        self.g[src].append(dst)

    def all_paths(self, src, dst, current_path=None):
        """ Return all paths from src to dst, avoiding current_path """
        if current_path is None:
            current_path = []
        if len(current_path) > self.MAX_PATH_LENGTH:
            raise RecursionError('Max path length {} exceeded'.format(self.MAX_PATH_LENGTH))
        current_path = current_path + [src]
        if src == dst:
            return [current_path]
        paths = []
        for next_node in self.g[src]:
            if next_node not in current_path:
                path_continuations = self.all_paths(next_node, dst, current_path)
                for new_path in path_continuations:
                    paths.append(new_path)
        return paths
