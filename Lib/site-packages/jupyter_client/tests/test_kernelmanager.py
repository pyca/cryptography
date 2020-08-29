"""Tests for the KernelManager"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.


import asyncio
import json
import os
import signal
import sys
import time
import threading
import multiprocessing as mp
import pytest

from async_generator import async_generator, yield_
from traitlets.config.loader import Config
from jupyter_core import paths
from jupyter_client import KernelManager, AsyncKernelManager
from subprocess import PIPE

from ..manager import start_new_kernel, start_new_async_kernel
from .utils import test_env, skip_win32, AsyncKernelManagerSubclass, AsyncKernelManagerWithCleanup

pjoin = os.path.join

TIMEOUT = 30


@pytest.fixture(autouse=True)
def env():
    env_patch = test_env()
    env_patch.start()
    yield
    env_patch.stop()


@pytest.fixture(params=['tcp', 'ipc'])
def transport(request):
    if sys.platform == 'win32' and request.param == 'ipc':  #
        pytest.skip("Transport 'ipc' not supported on Windows.")
    return request.param


@pytest.fixture
def config(transport):
    c = Config()
    c.KernelManager.transport = transport
    if transport == 'ipc':
        c.KernelManager.ip = 'test'
    return c


@pytest.fixture
def install_kernel():
    kernel_dir = pjoin(paths.jupyter_data_dir(), 'kernels', 'signaltest')
    os.makedirs(kernel_dir)
    with open(pjoin(kernel_dir, 'kernel.json'), 'w') as f:
        f.write(json.dumps({
            'argv': [sys.executable,
                     '-m', 'jupyter_client.tests.signalkernel',
                     '-f', '{connection_file}'],
            'display_name': "Signal Test Kernel",
            'env': {'TEST_VARS': '${TEST_VARS}:test_var_2'},
        }))


@pytest.fixture
def start_kernel():
    km, kc = start_new_kernel(kernel_name='signaltest')
    yield km, kc
    kc.stop_channels()
    km.shutdown_kernel()
    assert km.context.closed


@pytest.fixture
def start_kernel_w_env():
    kernel_cmd = [sys.executable,
                  '-m', 'jupyter_client.tests.signalkernel',
                  '-f', '{connection_file}']
    extra_env = {'TEST_VARS': '${TEST_VARS}:test_var_2'}

    km = KernelManager(kernel_name='signaltest')
    km.kernel_cmd = kernel_cmd
    km.extra_env = extra_env
    km.start_kernel()
    kc = km.client()
    kc.start_channels()

    kc.wait_for_ready(timeout=60)

    yield km, kc
    kc.stop_channels()
    km.shutdown_kernel()


@pytest.fixture
def km(config):
    km = KernelManager(config=config)
    return km


@pytest.fixture
def zmq_context():
    import zmq
    ctx = zmq.Context()
    yield ctx
    ctx.term()


@pytest.fixture(params=[AsyncKernelManager, AsyncKernelManagerSubclass, AsyncKernelManagerWithCleanup])
def async_km(request, config):
    km = request.param(config=config)
    return km


@pytest.fixture
@async_generator  # This is only necessary while Python 3.5 is support afterwhich both it and yield_() can be removed
async def start_async_kernel():
    km, kc = await start_new_async_kernel(kernel_name='signaltest')
    await yield_((km, kc))
    kc.stop_channels()
    await km.shutdown_kernel()
    assert km.context.closed


class TestKernelManager:

    def test_lifecycle(self, km):
        km.start_kernel(stdout=PIPE, stderr=PIPE)
        assert km.is_alive()
        km.restart_kernel(now=True)
        assert km.is_alive()
        km.interrupt_kernel()
        assert isinstance(km, KernelManager)
        km.shutdown_kernel(now=True)
        assert km.context.closed

    def test_get_connect_info(self, km):
        cinfo = km.get_connection_info()
        keys = sorted(cinfo.keys())
        expected = sorted([
            'ip', 'transport',
            'hb_port', 'shell_port', 'stdin_port', 'iopub_port', 'control_port',
            'key', 'signature_scheme',
        ])
        assert keys == expected

    @pytest.mark.skipif(sys.platform == 'win32', reason="Windows doesn't support signals")
    def test_signal_kernel_subprocesses(self, install_kernel, start_kernel):

        km, kc = start_kernel

        def execute(cmd):
            kc.execute(cmd)
            reply = kc.get_shell_msg(TIMEOUT)
            content = reply['content']
            assert content['status'] == 'ok'
            return content

        N = 5
        for i in range(N):
            execute("start")
        time.sleep(1)  # make sure subprocs stay up
        reply = execute('check')
        assert reply['user_expressions']['poll'] == [None] * N
        
        # start a job on the kernel to be interrupted
        kc.execute('sleep')
        time.sleep(1)  # ensure sleep message has been handled before we interrupt
        km.interrupt_kernel()
        reply = kc.get_shell_msg(TIMEOUT)
        content = reply['content']
        assert content['status'] == 'ok'
        assert content['user_expressions']['interrupted']
        # wait up to 5s for subprocesses to handle signal
        for i in range(50):
            reply = execute('check')
            if reply['user_expressions']['poll'] != [-signal.SIGINT] * N:
                time.sleep(0.1)
            else:
                break
        # verify that subprocesses were interrupted
        assert reply['user_expressions']['poll'] == [-signal.SIGINT] * N

    def test_start_new_kernel(self, install_kernel, start_kernel):
        km, kc = start_kernel
        assert km.is_alive()
        assert kc.is_alive()
        assert km.context.closed is False

    def _env_test_body(self, kc):
        def execute(cmd):
            kc.execute(cmd)
            reply = kc.get_shell_msg(TIMEOUT)
            content = reply['content']
            assert content['status'] == 'ok'
            return content

        reply = execute('env')
        assert reply is not None
        assert reply['user_expressions']['env'] == 'test_var_1:test_var_2'

    def test_templated_kspec_env(self, install_kernel, start_kernel):
        km, kc = start_kernel
        assert km.is_alive()
        assert kc.is_alive()
        assert km.context.closed is False
        self._env_test_body(kc)

    def test_templated_extra_env(self, install_kernel, start_kernel_w_env):
        km, kc = start_kernel_w_env
        assert km.is_alive()
        assert kc.is_alive()
        assert km.context.closed is False
        self._env_test_body(kc)

    def test_cleanup_context(self, km):
        assert km.context is not None
        km.cleanup_resources(restart=False)
        assert km.context.closed

    def test_no_cleanup_shared_context(self, zmq_context):
        """kernel manager does not terminate shared context"""
        km = KernelManager(context=zmq_context)
        assert km.context == zmq_context
        assert km.context is not None

        km.cleanup_resources(restart=False)
        assert km.context.closed is False
        assert zmq_context.closed is False


class TestParallel:

    @pytest.mark.timeout(TIMEOUT)
    def test_start_sequence_kernels(self, config, install_kernel):
        """Ensure that a sequence of kernel startups doesn't break anything."""
        self._run_signaltest_lifecycle(config)
        self._run_signaltest_lifecycle(config)
        self._run_signaltest_lifecycle(config)

    @pytest.mark.timeout(TIMEOUT)
    def test_start_parallel_thread_kernels(self, config, install_kernel):
        if config.KernelManager.transport == 'ipc':  # FIXME
            pytest.skip("IPC transport is currently not working for this test!")
        self._run_signaltest_lifecycle(config)

        thread = threading.Thread(target=self._run_signaltest_lifecycle, args=(config,))
        thread2 = threading.Thread(target=self._run_signaltest_lifecycle, args=(config,))
        try:
            thread.start()
            thread2.start()
        finally:
            thread.join()
            thread2.join()

    @pytest.mark.timeout(TIMEOUT)
    def test_start_parallel_process_kernels(self, config, install_kernel):
        if config.KernelManager.transport == 'ipc':  # FIXME
            pytest.skip("IPC transport is currently not working for this test!")
        self._run_signaltest_lifecycle(config)
        thread = threading.Thread(target=self._run_signaltest_lifecycle, args=(config,))
        proc = mp.Process(target=self._run_signaltest_lifecycle, args=(config,))
        try:
            thread.start()
            proc.start()
        finally:
            thread.join()
            proc.join()

        assert proc.exitcode == 0

    @pytest.mark.timeout(TIMEOUT)
    def test_start_sequence_process_kernels(self, config, install_kernel):
        self._run_signaltest_lifecycle(config)
        proc = mp.Process(target=self._run_signaltest_lifecycle, args=(config,))
        try:
            proc.start()
        finally:
            proc.join()

        assert proc.exitcode == 0

    def _prepare_kernel(self, km, startup_timeout=TIMEOUT, **kwargs):
        km.start_kernel(**kwargs)
        kc = km.client()
        kc.start_channels()
        try:
            kc.wait_for_ready(timeout=startup_timeout)
        except RuntimeError:
            kc.stop_channels()
            km.shutdown_kernel()
            raise

        return kc

    def _run_signaltest_lifecycle(self, config=None):
        km = KernelManager(config=config, kernel_name='signaltest')
        kc = self._prepare_kernel(km, stdout=PIPE, stderr=PIPE)

        def execute(cmd):
            kc.execute(cmd)
            reply = kc.get_shell_msg(TIMEOUT)
            content = reply['content']
            assert content['status'] == 'ok'
            return content

        execute("start")
        assert km.is_alive()
        execute('check')
        assert km.is_alive()

        km.restart_kernel(now=True)
        assert km.is_alive()
        execute('check')

        km.shutdown_kernel()
        assert km.context.closed


@pytest.mark.asyncio
class TestAsyncKernelManager:

    async def test_lifecycle(self, async_km):
        await async_km.start_kernel(stdout=PIPE, stderr=PIPE)
        is_alive = await async_km.is_alive()
        assert is_alive
        await async_km.restart_kernel(now=True)
        is_alive = await async_km.is_alive()
        assert is_alive
        await async_km.interrupt_kernel()
        assert isinstance(async_km, AsyncKernelManager)
        await async_km.shutdown_kernel(now=True)
        is_alive = await async_km.is_alive()
        assert is_alive is False
        assert async_km.context.closed

    async def test_get_connect_info(self, async_km):
        cinfo = async_km.get_connection_info()
        keys = sorted(cinfo.keys())
        expected = sorted([
            'ip', 'transport',
            'hb_port', 'shell_port', 'stdin_port', 'iopub_port', 'control_port',
            'key', 'signature_scheme',
        ])
        assert keys == expected

    async def test_subclasses(self, async_km):
        await async_km.start_kernel(stdout=PIPE, stderr=PIPE)
        is_alive = await async_km.is_alive()
        assert is_alive
        assert isinstance(async_km, AsyncKernelManager)
        await async_km.shutdown_kernel(now=True)
        is_alive = await async_km.is_alive()
        assert is_alive is False
        assert async_km.context.closed

        if isinstance(async_km, AsyncKernelManagerWithCleanup):
            assert async_km.which_cleanup == "cleanup"
        elif isinstance(async_km, AsyncKernelManagerSubclass):
            assert async_km.which_cleanup == "cleanup_resources"
        else:
            assert hasattr(async_km, "which_cleanup") is False

    @pytest.mark.timeout(10)
    @pytest.mark.skipif(sys.platform == 'win32', reason="Windows doesn't support signals")
    async def test_signal_kernel_subprocesses(self, install_kernel, start_async_kernel):

        km, kc = start_async_kernel

        async def execute(cmd):
            kc.execute(cmd)
            reply = await kc.get_shell_msg(TIMEOUT)
            content = reply['content']
            assert content['status'] == 'ok'
            return content
        # Ensure that shutdown_kernel and stop_channels are called at the end of the test.
        # Note: we cannot use addCleanup(<func>) for these since it doesn't prpperly handle
        # coroutines - which km.shutdown_kernel now is.
        N = 5
        for i in range(N):
            await execute("start")
        await asyncio.sleep(1)  # make sure subprocs stay up
        reply = await execute('check')
        assert reply['user_expressions']['poll'] == [None] * N

        # start a job on the kernel to be interrupted
        kc.execute('sleep')
        await asyncio.sleep(1)  # ensure sleep message has been handled before we interrupt
        await km.interrupt_kernel()
        reply = await kc.get_shell_msg(TIMEOUT)
        content = reply['content']
        assert content['status'] == 'ok'
        assert content['user_expressions']['interrupted'] is True
        # wait up to 5s for subprocesses to handle signal
        for i in range(50):
            reply = await execute('check')
            if reply['user_expressions']['poll'] != [-signal.SIGINT] * N:
                await asyncio.sleep(0.1)
            else:
                break
        # verify that subprocesses were interrupted
        assert reply['user_expressions']['poll'] == [-signal.SIGINT] * N

    @pytest.mark.timeout(10)
    async def test_start_new_async_kernel(self, install_kernel, start_async_kernel):
        km, kc = start_async_kernel
        is_alive = await km.is_alive()
        assert is_alive
        is_alive = await kc.is_alive()
        assert is_alive
