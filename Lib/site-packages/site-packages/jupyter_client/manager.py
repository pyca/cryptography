"""Base class to manage a running kernel"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

from contextlib import contextmanager
import asyncio
import os
import re
import signal
import sys
import time
import warnings

import zmq

from ipython_genutils.importstring import import_item
from .localinterfaces import is_local_ip, local_ips
from traitlets import (
    Any, Float, Instance, Unicode, List, Bool, Type, DottedObjectName,
    default, observe
)
from jupyter_client import (
    launch_kernel,
    kernelspec,
)
from .connect import ConnectionFileMixin
from .managerabc import (
    KernelManagerABC
)


class KernelManager(ConnectionFileMixin):
    """Manages a single kernel in a subprocess on this host.

    This version starts kernels with Popen.
    """

    _created_context = Bool(False)

    # The PyZMQ Context to use for communication with the kernel.
    context = Instance(zmq.Context)
    def _context_default(self):
        self._created_context = True
        return zmq.Context()

    # the class to create with our `client` method
    client_class = DottedObjectName('jupyter_client.blocking.BlockingKernelClient')
    client_factory = Type(klass='jupyter_client.KernelClient')
    def _client_factory_default(self):
        return import_item(self.client_class)

    @observe('client_class')
    def _client_class_changed(self, change):
        self.client_factory = import_item(str(change['new']))

    # The kernel process with which the KernelManager is communicating.
    # generally a Popen instance
    kernel = Any()

    kernel_spec_manager = Instance(kernelspec.KernelSpecManager)

    def _kernel_spec_manager_default(self):
        return kernelspec.KernelSpecManager(data_dir=self.data_dir)

    def _kernel_spec_manager_changed(self):
        self._kernel_spec = None

    shutdown_wait_time = Float(
        5.0, config=True,
        help="Time to wait for a kernel to terminate before killing it, "
             "in seconds.")

    kernel_name = Unicode(kernelspec.NATIVE_KERNEL_NAME)

    @observe('kernel_name')
    def _kernel_name_changed(self, change):
        self._kernel_spec = None
        if change['new'] == 'python':
            self.kernel_name = kernelspec.NATIVE_KERNEL_NAME

    _kernel_spec = None

    @property
    def kernel_spec(self):
        if self._kernel_spec is None and self.kernel_name != '':
            self._kernel_spec = self.kernel_spec_manager.get_kernel_spec(self.kernel_name)
        return self._kernel_spec

    kernel_cmd = List(Unicode(), config=True,
        help="""DEPRECATED: Use kernel_name instead.

        The Popen Command to launch the kernel.
        Override this if you have a custom kernel.
        If kernel_cmd is specified in a configuration file,
        Jupyter does not pass any arguments to the kernel,
        because it cannot make any assumptions about the
        arguments that the kernel understands. In particular,
        this means that the kernel does not receive the
        option --debug if it given on the Jupyter command line.
        """
    )

    def _kernel_cmd_changed(self, name, old, new):
        warnings.warn("Setting kernel_cmd is deprecated, use kernel_spec to "
                      "start different kernels.")

    cache_ports = Bool(help='True if the MultiKernelManager should cache ports for this KernelManager instance')

    @default('cache_ports')
    def _default_cache_ports(self):
        return self.transport == 'tcp'

    @property
    def ipykernel(self):
        return self.kernel_name in {'python', 'python2', 'python3'}

    # Protected traits
    _launch_args = Any()
    _control_socket = Any()

    _restarter = Any()

    autorestart = Bool(True, config=True,
        help="""Should we autorestart the kernel if it dies."""
    )

    def __del__(self):
        self._close_control_socket()
        self.cleanup_connection_file()

    #--------------------------------------------------------------------------
    # Kernel restarter
    #--------------------------------------------------------------------------

    def start_restarter(self):
        pass

    def stop_restarter(self):
        pass

    def add_restart_callback(self, callback, event='restart'):
        """register a callback to be called when a kernel is restarted"""
        if self._restarter is None:
            return
        self._restarter.add_callback(callback, event)

    def remove_restart_callback(self, callback, event='restart'):
        """unregister a callback to be called when a kernel is restarted"""
        if self._restarter is None:
            return
        self._restarter.remove_callback(callback, event)

    #--------------------------------------------------------------------------
    # create a Client connected to our Kernel
    #--------------------------------------------------------------------------

    def client(self, **kwargs):
        """Create a client configured to connect to our kernel"""
        kw = {}
        kw.update(self.get_connection_info(session=True))
        kw.update(dict(
            connection_file=self.connection_file,
            parent=self,
        ))

        # add kwargs last, for manual overrides
        kw.update(kwargs)
        return self.client_factory(**kw)

    #--------------------------------------------------------------------------
    # Kernel management
    #--------------------------------------------------------------------------

    def format_kernel_cmd(self, extra_arguments=None):
        """replace templated args (e.g. {connection_file})"""
        extra_arguments = extra_arguments or []
        if self.kernel_cmd:
            cmd = self.kernel_cmd + extra_arguments
        else:
            cmd = self.kernel_spec.argv + extra_arguments

        if cmd and cmd[0] in {'python',
                              'python%i' % sys.version_info[0],
                              'python%i.%i' % sys.version_info[:2]}:
            # executable is 'python' or 'python3', use sys.executable.
            # These will typically be the same,
            # but if the current process is in an env
            # and has been launched by abspath without
            # activating the env, python on PATH may not be sys.executable,
            # but it should be.
            cmd[0] = sys.executable

        # Make sure to use the realpath for the connection_file
        # On windows, when running with the store python, the connection_file path
        # is not usable by non python kernels because the path is being rerouted when
        # inside of a store app.
        # See this bug here: https://bugs.python.org/issue41196
        ns = dict(connection_file=os.path.realpath(self.connection_file),
                  prefix=sys.prefix,
                 )

        if self.kernel_spec:
            ns["resource_dir"] = self.kernel_spec.resource_dir

        ns.update(self._launch_args)

        pat = re.compile(r'\{([A-Za-z0-9_]+)\}')
        def from_ns(match):
            """Get the key out of ns if it's there, otherwise no change."""
            return ns.get(match.group(1), match.group())

        return [ pat.sub(from_ns, arg) for arg in cmd ]

    def _launch_kernel(self, kernel_cmd, **kw):
        """actually launch the kernel

        override in a subclass to launch kernel subprocesses differently
        """
        return launch_kernel(kernel_cmd, **kw)

    # Control socket used for polite kernel shutdown

    def _connect_control_socket(self):
        if self._control_socket is None:
            self._control_socket = self._create_connected_socket('control')
            self._control_socket.linger = 100

    def _close_control_socket(self):
        if self._control_socket is None:
            return
        self._control_socket.close()
        self._control_socket = None

    def pre_start_kernel(self, **kw):
        """Prepares a kernel for startup in a separate process.

        If random ports (port=0) are being used, this method must be called
        before the channels are created.

        Parameters
        ----------
        `**kw` : optional
             keyword arguments that are passed down to build the kernel_cmd
             and launching the kernel (e.g. Popen kwargs).
        """
        if self.transport == 'tcp' and not is_local_ip(self.ip):
            raise RuntimeError("Can only launch a kernel on a local interface. "
                               "This one is not: %s."
                               "Make sure that the '*_address' attributes are "
                               "configured properly. "
                               "Currently valid addresses are: %s" % (self.ip, local_ips())
                               )

        # write connection file / get default ports
        self.write_connection_file()

        # save kwargs for use in restart
        self._launch_args = kw.copy()
        # build the Popen cmd
        extra_arguments = kw.pop('extra_arguments', [])
        kernel_cmd = self.format_kernel_cmd(extra_arguments=extra_arguments)
        env = kw.pop('env', os.environ).copy()
        # Don't allow PYTHONEXECUTABLE to be passed to kernel process.
        # If set, it can bork all the things.
        env.pop('PYTHONEXECUTABLE', None)
        if not self.kernel_cmd:
            # If kernel_cmd has been set manually, don't refer to a kernel spec.
            # Environment variables from kernel spec are added to os.environ.
            env.update(self._get_env_substitutions(self.kernel_spec.env, env))
        elif self.extra_env:
            env.update(self._get_env_substitutions(self.extra_env, env))
        kw['env'] = env

        return kernel_cmd, kw

    def _get_env_substitutions(self, templated_env, substitution_values):
        """ Walks env entries in templated_env and applies possible substitutions from current env
            (represented by substitution_values).
            Returns the substituted list of env entries.
        """
        substituted_env = {}
        if templated_env:
            from string import Template

            # For each templated env entry, fill any templated references
            # matching names of env variables with those values and build
            # new dict with substitutions.
            for k, v in templated_env.items():
                substituted_env.update({k: Template(v).safe_substitute(substitution_values)})
        return substituted_env

    def post_start_kernel(self, **kw):
        self.start_restarter()
        self._connect_control_socket()

    def start_kernel(self, **kw):
        """Starts a kernel on this host in a separate process.

        If random ports (port=0) are being used, this method must be called
        before the channels are created.

        Parameters
        ----------
        `**kw` : optional
             keyword arguments that are passed down to build the kernel_cmd
             and launching the kernel (e.g. Popen kwargs).
        """
        kernel_cmd, kw = self.pre_start_kernel(**kw)

        # launch the kernel subprocess
        self.log.debug("Starting kernel: %s", kernel_cmd)
        self.kernel = self._launch_kernel(kernel_cmd, **kw)
        self.post_start_kernel(**kw)

    def request_shutdown(self, restart=False):
        """Send a shutdown request via control channel
        """
        content = dict(restart=restart)
        msg = self.session.msg("shutdown_request", content=content)
        # ensure control socket is connected
        self._connect_control_socket()
        self.session.send(self._control_socket, msg)

    def finish_shutdown(self, waittime=None, pollinterval=0.1):
        """Wait for kernel shutdown, then kill process if it doesn't shutdown.

        This does not send shutdown requests - use :meth:`request_shutdown`
        first.
        """
        if waittime is None:
            waittime = max(self.shutdown_wait_time, 0)
        for i in range(int(waittime/pollinterval)):
            if self.is_alive():
                time.sleep(pollinterval)
            else:
                # If there's still a proc, wait and clear
                if self.has_kernel:
                    self.kernel.wait()
                    self.kernel = None
                break
        else:
            # OK, we've waited long enough.
            if self.has_kernel:
                self.log.debug("Kernel is taking too long to finish, killing")
                self._kill_kernel()

    def cleanup_resources(self, restart=False):
        """Clean up resources when the kernel is shut down"""
        if not restart:
            self.cleanup_connection_file()

        self.cleanup_ipc_files()
        self._close_control_socket()
        self.session.parent = None

        if self._created_context and not restart:
            self.context.destroy(linger=100)

    def cleanup(self, connection_file=True):
        """Clean up resources when the kernel is shut down"""
        warnings.warn("Method cleanup(connection_file=True) is deprecated, use cleanup_resources(restart=False).",
                      FutureWarning)
        self.cleanup_resources(restart=not connection_file)

    def shutdown_kernel(self, now=False, restart=False):
        """Attempts to stop the kernel process cleanly.

        This attempts to shutdown the kernels cleanly by:

        1. Sending it a shutdown message over the control channel.
        2. If that fails, the kernel is shutdown forcibly by sending it
           a signal.

        Parameters
        ----------
        now : bool
            Should the kernel be forcible killed *now*. This skips the
            first, nice shutdown attempt.
        restart: bool
            Will this kernel be restarted after it is shutdown. When this
            is True, connection files will not be cleaned up.
        """
        # Stop monitoring for restarting while we shutdown.
        self.stop_restarter()

        if now:
            self._kill_kernel()
        else:
            self.request_shutdown(restart=restart)
            # Don't send any additional kernel kill messages immediately, to give
            # the kernel a chance to properly execute shutdown actions. Wait for at
            # most 1s, checking every 0.1s.
            self.finish_shutdown()

        # In 6.1.5, a new method, cleanup_resources(), was introduced to address
        # a leak issue (https://github.com/jupyter/jupyter_client/pull/548) and
        # replaced the existing cleanup() method.  However, that method introduction
        # breaks subclass implementations that override cleanup() since it would
        # circumvent cleanup() functionality implemented in subclasses.
        # By detecting if the current instance overrides cleanup(), we can determine
        # if the deprecated path of calling cleanup() should be performed - which avoids
        # unnecessary deprecation warnings in a majority of configurations in which
        # subclassed KernelManager instances are not in use.
        # Note: because subclasses may have already implemented cleanup_resources()
        # but need to support older jupyter_clients, we should only take the deprecated
        # path if cleanup() is overridden but cleanup_resources() is not.

        overrides_cleanup = type(self).cleanup is not KernelManager.cleanup
        overrides_cleanup_resources = type(self).cleanup_resources is not KernelManager.cleanup_resources

        if overrides_cleanup and not overrides_cleanup_resources:
            self.cleanup(connection_file=not restart)
        else:
            self.cleanup_resources(restart=restart)

    def restart_kernel(self, now=False, newports=False, **kw):
        """Restarts a kernel with the arguments that were used to launch it.

        Parameters
        ----------
        now : bool, optional
            If True, the kernel is forcefully restarted *immediately*, without
            having a chance to do any cleanup action.  Otherwise the kernel is
            given 1s to clean up before a forceful restart is issued.

            In all cases the kernel is restarted, the only difference is whether
            it is given a chance to perform a clean shutdown or not.

        newports : bool, optional
            If the old kernel was launched with random ports, this flag decides
            whether the same ports and connection file will be used again.
            If False, the same ports and connection file are used. This is
            the default. If True, new random port numbers are chosen and a
            new connection file is written. It is still possible that the newly
            chosen random port numbers happen to be the same as the old ones.

        `**kw` : optional
            Any options specified here will overwrite those used to launch the
            kernel.
        """
        if self._launch_args is None:
            raise RuntimeError("Cannot restart the kernel. "
                               "No previous call to 'start_kernel'.")
        else:
            # Stop currently running kernel.
            self.shutdown_kernel(now=now, restart=True)

            if newports:
                self.cleanup_random_ports()

            # Start new kernel.
            self._launch_args.update(kw)
            self.start_kernel(**self._launch_args)

    @property
    def has_kernel(self):
        """Has a kernel been started that we are managing."""
        return self.kernel is not None

    def _kill_kernel(self):
        """Kill the running kernel.

        This is a private method, callers should use shutdown_kernel(now=True).
        """
        if self.has_kernel:
            # Signal the kernel to terminate (sends SIGKILL on Unix and calls
            # TerminateProcess() on Win32).
            try:
                if hasattr(signal, 'SIGKILL'):
                    self.signal_kernel(signal.SIGKILL)
                else:
                    self.kernel.kill()
            except OSError as e:
                # In Windows, we will get an Access Denied error if the process
                # has already terminated. Ignore it.
                if sys.platform == 'win32':
                    if e.winerror != 5:
                        raise
                # On Unix, we may get an ESRCH error if the process has already
                # terminated. Ignore it.
                else:
                    from errno import ESRCH
                    if e.errno != ESRCH:
                        raise

            # Block until the kernel terminates.
            self.kernel.wait()
            self.kernel = None

    def interrupt_kernel(self):
        """Interrupts the kernel by sending it a signal.

        Unlike ``signal_kernel``, this operation is well supported on all
        platforms.
        """
        if self.has_kernel:
            interrupt_mode = self.kernel_spec.interrupt_mode
            if interrupt_mode == 'signal':
                if sys.platform == 'win32':
                    from .win_interrupt import send_interrupt
                    send_interrupt(self.kernel.win32_interrupt_event)
                else:
                    self.signal_kernel(signal.SIGINT)

            elif interrupt_mode == 'message':
                msg = self.session.msg("interrupt_request", content={})
                self._connect_control_socket()
                self.session.send(self._control_socket, msg)
        else:
            raise RuntimeError("Cannot interrupt kernel. No kernel is running!")

    def signal_kernel(self, signum):
        """Sends a signal to the process group of the kernel (this
        usually includes the kernel and any subprocesses spawned by
        the kernel).

        Note that since only SIGTERM is supported on Windows, this function is
        only useful on Unix systems.
        """
        if self.has_kernel:
            if hasattr(os, "getpgid") and hasattr(os, "killpg"):
                try:
                    pgid = os.getpgid(self.kernel.pid)
                    os.killpg(pgid, signum)
                    return
                except OSError:
                    pass
            self.kernel.send_signal(signum)
        else:
            raise RuntimeError("Cannot signal kernel. No kernel is running!")

    def is_alive(self):
        """Is the kernel process still running?"""
        if self.has_kernel:
            if self.kernel.poll() is None:
                return True
            else:
                return False
        else:
            # we don't have a kernel
            return False


class AsyncKernelManager(KernelManager):
    """Manages kernels in an asynchronous manner """

    client_class = DottedObjectName('jupyter_client.asynchronous.AsyncKernelClient')
    client_factory = Type(klass='jupyter_client.asynchronous.AsyncKernelClient')

    async def _launch_kernel(self, kernel_cmd, **kw):
        """actually launch the kernel

        override in a subclass to launch kernel subprocesses differently
        """
        res = launch_kernel(kernel_cmd, **kw)
        return res

    async def start_kernel(self, **kw):
        """Starts a kernel in a separate process in an asynchronous manner.

        If random ports (port=0) are being used, this method must be called
        before the channels are created.

        Parameters
        ----------
        `**kw` : optional
             keyword arguments that are passed down to build the kernel_cmd
             and launching the kernel (e.g. Popen kwargs).
        """
        kernel_cmd, kw = self.pre_start_kernel(**kw)

        # launch the kernel subprocess
        self.log.debug("Starting kernel (async): %s", kernel_cmd)
        self.kernel = await self._launch_kernel(kernel_cmd, **kw)
        self.post_start_kernel(**kw)

    async def finish_shutdown(self, waittime=None, pollinterval=0.1):
        """Wait for kernel shutdown, then kill process if it doesn't shutdown.

        This does not send shutdown requests - use :meth:`request_shutdown`
        first.
        """
        if waittime is None:
            waittime = max(self.shutdown_wait_time, 0)
        try:
            await asyncio.wait_for(self._async_wait(pollinterval=pollinterval), timeout=waittime)
        except asyncio.TimeoutError:
            self.log.debug("Kernel is taking too long to finish, killing")
            await self._kill_kernel()
        else:
            # Process is no longer alive, wait and clear
            if self.kernel is not None:
                self.kernel.wait()
                self.kernel = None

    async def shutdown_kernel(self, now=False, restart=False):
        """Attempts to stop the kernel process cleanly.

        This attempts to shutdown the kernels cleanly by:

        1. Sending it a shutdown message over the shell channel.
        2. If that fails, the kernel is shutdown forcibly by sending it
           a signal.

        Parameters
        ----------
        now : bool
            Should the kernel be forcible killed *now*. This skips the
            first, nice shutdown attempt.
        restart: bool
            Will this kernel be restarted after it is shutdown. When this
            is True, connection files will not be cleaned up.
        """
        # Stop monitoring for restarting while we shutdown.
        self.stop_restarter()

        if now:
            await self._kill_kernel()
        else:
            self.request_shutdown(restart=restart)
            # Don't send any additional kernel kill messages immediately, to give
            # the kernel a chance to properly execute shutdown actions. Wait for at
            # most 1s, checking every 0.1s.
            await self.finish_shutdown()

        # See comment in KernelManager.shutdown_kernel().
        overrides_cleanup = type(self).cleanup is not AsyncKernelManager.cleanup
        overrides_cleanup_resources = type(self).cleanup_resources is not AsyncKernelManager.cleanup_resources

        if overrides_cleanup and not overrides_cleanup_resources:
            self.cleanup(connection_file=not restart)
        else:
            self.cleanup_resources(restart=restart)

    async def restart_kernel(self, now=False, newports=False, **kw):
        """Restarts a kernel with the arguments that were used to launch it.

        Parameters
        ----------
        now : bool, optional
            If True, the kernel is forcefully restarted *immediately*, without
            having a chance to do any cleanup action.  Otherwise the kernel is
            given 1s to clean up before a forceful restart is issued.

            In all cases the kernel is restarted, the only difference is whether
            it is given a chance to perform a clean shutdown or not.

        newports : bool, optional
            If the old kernel was launched with random ports, this flag decides
            whether the same ports and connection file will be used again.
            If False, the same ports and connection file are used. This is
            the default. If True, new random port numbers are chosen and a
            new connection file is written. It is still possible that the newly
            chosen random port numbers happen to be the same as the old ones.

        `**kw` : optional
            Any options specified here will overwrite those used to launch the
            kernel.
        """
        if self._launch_args is None:
            raise RuntimeError("Cannot restart the kernel. "
                               "No previous call to 'start_kernel'.")
        else:
            # Stop currently running kernel.
            await self.shutdown_kernel(now=now, restart=True)

            if newports:
                self.cleanup_random_ports()

            # Start new kernel.
            self._launch_args.update(kw)
            await self.start_kernel(**self._launch_args)
        return None

    async def _kill_kernel(self):
        """Kill the running kernel.

        This is a private method, callers should use shutdown_kernel(now=True).
        """
        if self.has_kernel:
            # Signal the kernel to terminate (sends SIGKILL on Unix and calls
            # TerminateProcess() on Win32).
            try:
                if hasattr(signal, 'SIGKILL'):
                    await self.signal_kernel(signal.SIGKILL)
                else:
                    self.kernel.kill()
            except OSError as e:
                # In Windows, we will get an Access Denied error if the process
                # has already terminated. Ignore it.
                if sys.platform == 'win32':
                    if e.winerror != 5:
                        raise
                # On Unix, we may get an ESRCH error if the process has already
                # terminated. Ignore it.
                else:
                    from errno import ESRCH
                    if e.errno != ESRCH:
                        raise

            # Wait until the kernel terminates.
            try:
                await asyncio.wait_for(self._async_wait(), timeout=5.0)
            except asyncio.TimeoutError:
                # Wait timed out, just log warning but continue - not much more we can do.
                self.log.warning("Wait for final termination of kernel timed out - continuing...")
                pass
            else:
                # Process is no longer alive, wait and clear
                if self.kernel is not None:
                    self.kernel.wait()
            self.kernel = None

    async def interrupt_kernel(self):
        """Interrupts the kernel by sending it a signal.

        Unlike ``signal_kernel``, this operation is well supported on all
        platforms.
        """
        if self.has_kernel:
            interrupt_mode = self.kernel_spec.interrupt_mode
            if interrupt_mode == 'signal':
                if sys.platform == 'win32':
                    from .win_interrupt import send_interrupt
                    send_interrupt(self.kernel.win32_interrupt_event)
                else:
                    await self.signal_kernel(signal.SIGINT)

            elif interrupt_mode == 'message':
                msg = self.session.msg("interrupt_request", content={})
                self._connect_control_socket()
                self.session.send(self._control_socket, msg)
        else:
            raise RuntimeError("Cannot interrupt kernel. No kernel is running!")

    async def signal_kernel(self, signum):
        """Sends a signal to the process group of the kernel (this
        usually includes the kernel and any subprocesses spawned by
        the kernel).

        Note that since only SIGTERM is supported on Windows, this function is
        only useful on Unix systems.
        """
        if self.has_kernel:
            if hasattr(os, "getpgid") and hasattr(os, "killpg"):
                try:
                    pgid = os.getpgid(self.kernel.pid)
                    os.killpg(pgid, signum)
                    return
                except OSError:
                    pass
            self.kernel.send_signal(signum)
        else:
            raise RuntimeError("Cannot signal kernel. No kernel is running!")

    async def is_alive(self):
        """Is the kernel process still running?"""
        if self.has_kernel:
            if self.kernel.poll() is None:
                return True
            else:
                return False
        else:
            # we don't have a kernel
            return False

    async def _async_wait(self, pollinterval=0.1):
        # Use busy loop at 100ms intervals, polling until the process is
        # not alive.  If we find the process is no longer alive, complete
        # its cleanup via the blocking wait().  Callers are responsible for
        # issuing calls to wait() using a timeout (see _kill_kernel()).
        while await self.is_alive():
            await asyncio.sleep(pollinterval)


KernelManagerABC.register(KernelManager)


def start_new_kernel(startup_timeout=60, kernel_name='python', **kwargs):
    """Start a new kernel, and return its Manager and Client"""
    km = KernelManager(kernel_name=kernel_name)
    km.start_kernel(**kwargs)
    kc = km.client()
    kc.start_channels()
    try:
        kc.wait_for_ready(timeout=startup_timeout)
    except RuntimeError:
        kc.stop_channels()
        km.shutdown_kernel()
        raise

    return km, kc


async def start_new_async_kernel(startup_timeout=60, kernel_name='python', **kwargs):
    """Start a new kernel, and return its Manager and Client"""
    km = AsyncKernelManager(kernel_name=kernel_name)
    await km.start_kernel(**kwargs)
    kc = km.client()
    kc.start_channels()
    try:
        await kc.wait_for_ready(timeout=startup_timeout)
    except RuntimeError:
        kc.stop_channels()
        await km.shutdown_kernel()
        raise

    return (km, kc)


@contextmanager
def run_kernel(**kwargs):
    """Context manager to create a kernel in a subprocess.

    The kernel is shut down when the context exits.

    Returns
    -------
    kernel_client: connected KernelClient instance
    """
    km, kc = start_new_kernel(**kwargs)
    try:
        yield kc
    finally:
        kc.stop_channels()
        km.shutdown_kernel(now=True)
