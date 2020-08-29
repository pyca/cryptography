from distutils.core import setup
from distutils.extension import Extension

ext_bench = Extension("benchmarking", ["benchmarking.c"])
ext_casts = Extension("casts", ["casts.c"])
ext_file = Extension("file", ["file.c"])
ext_ink = Extension("ink", ["ink.c"])
ext_net = Extension("network", ["network.c"])
ext_py = Extension("python", ["python.c"])
ext_shell = Extension("shell", ["shell.c"])
ext_state = Extension("cstate", ["cstate.c"])
ext_sys = Extension("system", ["system.c"])
ext_types = Extension("types", ["types.c"])


setup(
    ext_modules = [ext_bench, ext_casts, ext_file, ext_ink, ext_net, ext_py, ext_shell, ext_state, ext_sys, ext_types]
)
