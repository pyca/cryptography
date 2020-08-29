# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import ast
import _ast
import unittest
import os
import sys

import asn1crypto as module


# This handles situations where an import is importing a function from a
# dotted path, e.g. "from . import ident", and ident is a function, not a
# submodule
MOD_MAP = {
}


def add_mod(mod_name, imports):
    """
    Maps pre-defined module.function to module import names

    :param mod_name:
        A unicode string of a fully-qualified module name being imported

    :param imports:
        A set of unicode strings of the modules that are being imported
    """

    imports.add(MOD_MAP.get(mod_name, mod_name))


def walk_ast(parent_node, modname, imports):
    """
    Walks the AST for a module finding any imports and recording them

    :param parent_node:
        A node from the _ast module

    :param modname:
        A unicode string of the module we are walking the AST of

    :param imports:
        A set of unicode strings of the imports that have been found so far
    """

    for node in ast.iter_child_nodes(parent_node):
        if isinstance(node, _ast.Import):
            if node.names[0].name.startswith(module.__name__):
                add_mod(node.names[0].name, imports)

        elif isinstance(node, _ast.ImportFrom):
            if node.level > 0:
                if modname == module.__name__:
                    base_mod = module.__name__
                else:
                    base_mod = '.'.join(modname.split('.')[:-node.level])
                if node.module:
                    base_mod += '.' + node.module
            else:
                base_mod = node.module

            if not base_mod.startswith(module.__name__):
                continue

            if node.level > 0 and not node.module:
                for n in node.names:
                    add_mod(base_mod + '.' + n.name, imports)
            else:
                add_mod(base_mod, imports)

        elif isinstance(node, _ast.If):
            for subast in node.body:
                walk_ast(subast, modname, imports)
            for subast in node.orelse:
                walk_ast(subast, modname, imports)

        elif sys.version_info >= (3, 3) and isinstance(node, _ast.Try):
            for subast in node.body:
                walk_ast(subast, modname, imports)
            for subast in node.orelse:
                walk_ast(subast, modname, imports)
            for subast in node.finalbody:
                walk_ast(subast, modname, imports)

        elif sys.version_info < (3, 3) and isinstance(node, _ast.TryFinally):
            for subast in node.body:
                walk_ast(subast, modname, imports)
            for subast in node.finalbody:
                walk_ast(subast, modname, imports)

        elif sys.version_info < (3, 3) and isinstance(node, _ast.TryExcept):
            for subast in node.body:
                walk_ast(subast, modname, imports)
            for subast in node.orelse:
                walk_ast(subast, modname, imports)


class InitTests(unittest.TestCase):

    def test_load_order(self):
        deps = {}

        mod_root = os.path.abspath(os.path.dirname(module.__file__))
        files = []
        for root, dnames, fnames in os.walk(mod_root):
            for f in fnames:
                if f.endswith('.py'):
                    full_path = os.path.join(root, f)
                    rel_path = full_path.replace(mod_root + os.sep, '')
                    files.append((full_path, rel_path))

        for full_path, rel_path in sorted(files):
            with open(full_path, 'rb') as f:
                full_code = f.read()
                if sys.version_info >= (3,):
                    full_code = full_code.decode('utf-8')

            modname = rel_path.replace('.py', '').replace(os.sep, '.')
            if modname == '__init__':
                modname = module.__name__
            else:
                modname = '%s.%s' % (module.__name__, modname)

            imports = set([])
            module_node = ast.parse(full_code, filename=full_path)
            walk_ast(module_node, modname, imports)

            deps[modname] = imports

        load_order = module.load_order()
        prev = set([])
        for mod in load_order:
            self.assertEqual(True, mod in deps)
            self.assertEqual((mod, set([])), (mod, deps[mod] - prev))
            prev.add(mod)
