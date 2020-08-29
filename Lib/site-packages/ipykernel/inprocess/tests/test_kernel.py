# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

from __future__ import print_function

import sys
import unittest

from ipykernel.inprocess.blocking import BlockingInProcessKernelClient
from ipykernel.inprocess.manager import InProcessKernelManager
from ipykernel.inprocess.ipkernel import InProcessKernel
from ipykernel.tests.utils import assemble_output
from IPython.testing.decorators import skipif_not_matplotlib
from IPython.utils.io import capture_output
from ipython_genutils import py3compat

if py3compat.PY3:
    from io import StringIO
else:
    from StringIO import StringIO


def _init_asyncio_patch():
    """set default asyncio policy to be compatible with tornado

    Tornado 6 (at least) is not compatible with the default
    asyncio implementation on Windows

    Pick the older SelectorEventLoopPolicy on Windows
    if the known-incompatible default policy is in use.

    do this as early as possible to make it a low priority and overrideable

    ref: https://github.com/tornadoweb/tornado/issues/2608

    FIXME: if/when tornado supports the defaults in asyncio,
           remove and bump tornado requirement for py38
    """
    if sys.platform.startswith("win") and sys.version_info >= (3, 8):
        import asyncio
        try:
            from asyncio import (
                WindowsProactorEventLoopPolicy,
                WindowsSelectorEventLoopPolicy,
            )
        except ImportError:
            pass
            # not affected
        else:
            if type(asyncio.get_event_loop_policy()) is WindowsProactorEventLoopPolicy:
                # WindowsProactorEventLoopPolicy is not compatible with tornado 6
                # fallback to the pre-3.8 default of Selector
                asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())


class InProcessKernelTestCase(unittest.TestCase):

    def setUp(self):
        _init_asyncio_patch()
        self.km = InProcessKernelManager()
        self.km.start_kernel()
        self.kc = self.km.client()
        self.kc.start_channels()
        self.kc.wait_for_ready()

    @skipif_not_matplotlib
    def test_pylab(self):
        """Does %pylab work in the in-process kernel?"""
        kc = self.kc
        kc.execute('%pylab')
        out, err = assemble_output(kc.iopub_channel)
        self.assertIn('matplotlib', out)

    def test_raw_input(self):
        """ Does the in-process kernel handle raw_input correctly?
        """
        io = StringIO('foobar\n')
        sys_stdin = sys.stdin
        sys.stdin = io
        try:
            if py3compat.PY3:
                self.kc.execute('x = input()')
            else:
                self.kc.execute('x = raw_input()')
        finally:
            sys.stdin = sys_stdin
        assert self.km.kernel.shell.user_ns.get('x') == 'foobar'

    def test_stdout(self):
        """ Does the in-process kernel correctly capture IO?
        """
        kernel = InProcessKernel()

        with capture_output() as io:
            kernel.shell.run_cell('print("foo")')
        assert io.stdout == 'foo\n'

        kc = BlockingInProcessKernelClient(kernel=kernel, session=kernel.session)
        kernel.frontends.append(kc)
        kc.execute('print("bar")')
        out, err = assemble_output(kc.iopub_channel)
        assert out == 'bar\n'

    def test_getpass_stream(self):
        "Tests that kernel getpass accept the stream parameter"
        kernel = InProcessKernel()
        kernel._allow_stdin = True
        kernel._input_request = lambda *args, **kwargs : None

        kernel.getpass(stream='non empty')
