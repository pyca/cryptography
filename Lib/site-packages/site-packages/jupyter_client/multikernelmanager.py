"""A kernel manager for multiple kernels"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import os
import uuid
import socket

import zmq

from traitlets.config.configurable import LoggingConfigurable
from ipython_genutils.importstring import import_item
from traitlets import (
    Any, Bool, Dict, DottedObjectName, Instance, Unicode, default, observe
)

from .kernelspec import NATIVE_KERNEL_NAME, KernelSpecManager
from .manager import KernelManager, AsyncKernelManager


class DuplicateKernelError(Exception):
    pass


def kernel_method(f):
    """decorator for proxying MKM.method(kernel_id) to individual KMs by ID"""
    def wrapped(self, kernel_id, *args, **kwargs):
        # get the kernel
        km = self.get_kernel(kernel_id)
        method = getattr(km, f.__name__)
        # call the kernel's method
        r = method(*args, **kwargs)
        # last thing, call anything defined in the actual class method
        # such as logging messages
        f(self, kernel_id, *args, **kwargs)
        # return the method result
        return r
    return wrapped


class MultiKernelManager(LoggingConfigurable):
    """A class for managing multiple kernels."""

    default_kernel_name = Unicode(NATIVE_KERNEL_NAME, config=True,
        help="The name of the default kernel to start"
    )

    kernel_spec_manager = Instance(KernelSpecManager, allow_none=True)

    kernel_manager_class = DottedObjectName(
        "jupyter_client.ioloop.IOLoopKernelManager", config=True,
        help="""The kernel manager class.  This is configurable to allow
        subclassing of the KernelManager for customized behavior.
        """
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Cache all the currently used ports
        self.currently_used_ports = set()

    @observe('kernel_manager_class')
    def _kernel_manager_class_changed(self, change):
        self.kernel_manager_factory = self._create_kernel_manager_factory()

    kernel_manager_factory = Any(help="this is kernel_manager_class after import")

    @default('kernel_manager_factory')
    def _kernel_manager_factory_default(self):
        return self._create_kernel_manager_factory()

    def _create_kernel_manager_factory(self):
        kernel_manager_ctor = import_item(self.kernel_manager_class)

        def create_kernel_manager(*args, **kwargs):
            if self.shared_context:
                if self.context.closed:
                    # recreate context if closed
                    self.context = self._context_default()
                kwargs.setdefault("context", self.context)
            km = kernel_manager_ctor(*args, **kwargs)

            if km.cache_ports:
                km.shell_port = self._find_available_port(km.ip)
                km.iopub_port = self._find_available_port(km.ip)
                km.stdin_port = self._find_available_port(km.ip)
                km.hb_port = self._find_available_port(km.ip)
                km.control_port = self._find_available_port(km.ip)

            return km

        return create_kernel_manager

    def _find_available_port(self, ip):
        while True:
            tmp_sock = socket.socket()
            tmp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\0' * 8)
            tmp_sock.bind((ip, 0))
            port = tmp_sock.getsockname()[1]
            tmp_sock.close()

            # This is a workaround for https://github.com/jupyter/jupyter_client/issues/487
            # We prevent two kernels to have the same ports.
            if port not in self.currently_used_ports:
                self.currently_used_ports.add(port)

                return port

    shared_context = Bool(
        True,
        config=True,
        help="Share a single zmq.Context to talk to all my kernels",
    )

    _created_context = Bool(False)

    context = Instance('zmq.Context')

    @default("context")
    def _context_default(self):
        self._created_context = True
        return zmq.Context()

    def __del__(self):
        if self._created_context and self.context and not self.context.closed:
            if self.log:
                self.log.debug("Destroying zmq context for %s", self)
            self.context.destroy()
        try:
            super_del = super().__del__
        except AttributeError:
            pass
        else:
            super_del()

    connection_dir = Unicode('')

    _kernels = Dict()

    def list_kernel_ids(self):
        """Return a list of the kernel ids of the active kernels."""
        # Create a copy so we can iterate over kernels in operations
        # that delete keys.
        return list(self._kernels.keys())

    def __len__(self):
        """Return the number of running kernels."""
        return len(self.list_kernel_ids())

    def __contains__(self, kernel_id):
        return kernel_id in self._kernels

    def pre_start_kernel(self, kernel_name, kwargs):
        # kwargs should be mutable, passing it as a dict argument.
        kernel_id = kwargs.pop('kernel_id', self.new_kernel_id(**kwargs))
        if kernel_id in self:
            raise DuplicateKernelError('Kernel already exists: %s' % kernel_id)

        if kernel_name is None:
            kernel_name = self.default_kernel_name
        # kernel_manager_factory is the constructor for the KernelManager
        # subclass we are using. It can be configured as any Configurable,
        # including things like its transport and ip.
        constructor_kwargs = {}
        if self.kernel_spec_manager:
            constructor_kwargs['kernel_spec_manager'] = self.kernel_spec_manager
        km = self.kernel_manager_factory(connection_file=os.path.join(
                    self.connection_dir, "kernel-%s.json" % kernel_id),
                    parent=self, log=self.log, kernel_name=kernel_name,
                    **constructor_kwargs
        )
        return km, kernel_name, kernel_id

    def start_kernel(self, kernel_name=None, **kwargs):
        """Start a new kernel.

        The caller can pick a kernel_id by passing one in as a keyword arg,
        otherwise one will be generated using new_kernel_id().

        The kernel ID for the newly started kernel is returned.
        """
        km, kernel_name, kernel_id = self.pre_start_kernel(kernel_name, kwargs)
        km.start_kernel(**kwargs)
        self._kernels[kernel_id] = km
        return kernel_id

    def shutdown_kernel(self, kernel_id, now=False, restart=False):
        """Shutdown a kernel by its kernel uuid.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to shutdown.
        now : bool
            Should the kernel be shutdown forcibly using a signal.
        restart : bool
            Will the kernel be restarted?
        """
        self.log.info("Kernel shutdown: %s" % kernel_id)

        km = self.get_kernel(kernel_id)

        ports = (
            km.shell_port, km.iopub_port, km.stdin_port,
            km.hb_port, km.control_port
        )

        km.shutdown_kernel(now=now, restart=restart)
        self.remove_kernel(kernel_id)

        if km.cache_ports and not restart:
            for port in ports:
                self.currently_used_ports.remove(port)

    @kernel_method
    def request_shutdown(self, kernel_id, restart=False):
        """Ask a kernel to shut down by its kernel uuid"""

    @kernel_method
    def finish_shutdown(self, kernel_id, waittime=None, pollinterval=0.1):
        """Wait for a kernel to finish shutting down, and kill it if it doesn't
        """
        self.log.info("Kernel shutdown: %s" % kernel_id)

    @kernel_method
    def cleanup(self, kernel_id, connection_file=True):
        """Clean up a kernel's resources"""

    @kernel_method
    def cleanup_resources(self, kernel_id, restart=False):
        """Clean up a kernel's resources"""

    def remove_kernel(self, kernel_id):
        """remove a kernel from our mapping.

        Mainly so that a kernel can be removed if it is already dead,
        without having to call shutdown_kernel.

        The kernel object is returned.
        """
        return self._kernels.pop(kernel_id)

    def shutdown_all(self, now=False):
        """Shutdown all kernels."""
        kids = self.list_kernel_ids()
        for kid in kids:
            self.request_shutdown(kid)
        for kid in kids:
            self.finish_shutdown(kid)

            # Determine which cleanup method to call
            # See comment in KernelManager.shutdown_kernel().
            km = self.get_kernel(kid)
            overrides_cleanup = type(km).cleanup is not KernelManager.cleanup
            overrides_cleanup_resources = type(km).cleanup_resources is not KernelManager.cleanup_resources

            if overrides_cleanup and not overrides_cleanup_resources:
                km.cleanup(connection_file=True)
            else:
                km.cleanup_resources(restart=False)

            self.remove_kernel(kid)

    @kernel_method
    def interrupt_kernel(self, kernel_id):
        """Interrupt (SIGINT) the kernel by its uuid.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to interrupt.
        """
        self.log.info("Kernel interrupted: %s" % kernel_id)

    @kernel_method
    def signal_kernel(self, kernel_id, signum):
        """Sends a signal to the kernel by its uuid.

        Note that since only SIGTERM is supported on Windows, this function
        is only useful on Unix systems.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to signal.
        """
        self.log.info("Signaled Kernel %s with %s" % (kernel_id, signum))

    @kernel_method
    def restart_kernel(self, kernel_id, now=False):
        """Restart a kernel by its uuid, keeping the same ports.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to interrupt.
        """
        self.log.info("Kernel restarted: %s" % kernel_id)

    @kernel_method
    def is_alive(self, kernel_id):
        """Is the kernel alive.

        This calls KernelManager.is_alive() which calls Popen.poll on the
        actual kernel subprocess.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel.
        """

    def _check_kernel_id(self, kernel_id):
        """check that a kernel id is valid"""
        if kernel_id not in self:
            raise KeyError("Kernel with id not found: %s" % kernel_id)

    def get_kernel(self, kernel_id):
        """Get the single KernelManager object for a kernel by its uuid.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel.
        """
        self._check_kernel_id(kernel_id)
        return self._kernels[kernel_id]

    @kernel_method
    def add_restart_callback(self, kernel_id, callback, event='restart'):
        """add a callback for the KernelRestarter"""

    @kernel_method
    def remove_restart_callback(self, kernel_id, callback, event='restart'):
        """remove a callback for the KernelRestarter"""

    @kernel_method
    def get_connection_info(self, kernel_id):
        """Return a dictionary of connection data for a kernel.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel.

        Returns
        =======
        connection_dict : dict
            A dict of the information needed to connect to a kernel.
            This includes the ip address and the integer port
            numbers of the different channels (stdin_port, iopub_port,
            shell_port, hb_port).
        """

    @kernel_method
    def connect_iopub(self, kernel_id, identity=None):
        """Return a zmq Socket connected to the iopub channel.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel
        identity : bytes (optional)
            The zmq identity of the socket

        Returns
        =======
        stream : zmq Socket or ZMQStream
        """

    @kernel_method
    def connect_shell(self, kernel_id, identity=None):
        """Return a zmq Socket connected to the shell channel.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel
        identity : bytes (optional)
            The zmq identity of the socket

        Returns
        =======
        stream : zmq Socket or ZMQStream
        """

    @kernel_method
    def connect_control(self, kernel_id, identity=None):
        """Return a zmq Socket connected to the control channel.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel
        identity : bytes (optional)
            The zmq identity of the socket

        Returns
        =======
        stream : zmq Socket or ZMQStream
        """

    @kernel_method
    def connect_stdin(self, kernel_id, identity=None):
        """Return a zmq Socket connected to the stdin channel.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel
        identity : bytes (optional)
            The zmq identity of the socket

        Returns
        =======
        stream : zmq Socket or ZMQStream
        """

    @kernel_method
    def connect_hb(self, kernel_id, identity=None):
        """Return a zmq Socket connected to the hb channel.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel
        identity : bytes (optional)
            The zmq identity of the socket

        Returns
        =======
        stream : zmq Socket or ZMQStream
        """

    def new_kernel_id(self, **kwargs):
        """
        Returns the id to associate with the kernel for this request. Subclasses may override
        this method to substitute other sources of kernel ids.
        :param kwargs:
        :return: string-ized version 4 uuid
        """
        return str(uuid.uuid4())


class AsyncMultiKernelManager(MultiKernelManager):

    kernel_manager_class = DottedObjectName(
        "jupyter_client.ioloop.AsyncIOLoopKernelManager", config=True,
        help="""The kernel manager class.  This is configurable to allow
        subclassing of the AsyncKernelManager for customized behavior.
        """
    )

    async def start_kernel(self, kernel_name=None, **kwargs):
        """Start a new kernel.

        The caller can pick a kernel_id by passing one in as a keyword arg,
        otherwise one will be generated using new_kernel_id().

        The kernel ID for the newly started kernel is returned.
        """
        km, kernel_name, kernel_id = self.pre_start_kernel(kernel_name, kwargs)
        if not isinstance(km, AsyncKernelManager):
            self.log.warning("Kernel manager class ({km_class}) is not an instance of 'AsyncKernelManager'!".
                             format(km_class=self.kernel_manager_class.__class__))
        await km.start_kernel(**kwargs)
        self._kernels[kernel_id] = km
        return kernel_id

    async def shutdown_kernel(self, kernel_id, now=False, restart=False):
        """Shutdown a kernel by its kernel uuid.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to shutdown.
        now : bool
            Should the kernel be shutdown forcibly using a signal.
        restart : bool
            Will the kernel be restarted?
        """
        self.log.info("Kernel shutdown: %s" % kernel_id)

        km = self.get_kernel(kernel_id)

        ports = (
            km.shell_port, km.iopub_port, km.stdin_port,
            km.hb_port, km.control_port
        )

        await km.shutdown_kernel(now, restart)
        self.remove_kernel(kernel_id)

        if km.cache_ports and not restart:
            for port in ports:
                self.currently_used_ports.remove(port)

    async def finish_shutdown(self, kernel_id, waittime=None, pollinterval=0.1):
        """Wait for a kernel to finish shutting down, and kill it if it doesn't
        """
        km = self.get_kernel(kernel_id)
        await km.finish_shutdown(waittime, pollinterval)
        self.log.info("Kernel shutdown: %s" % kernel_id)

    async def interrupt_kernel(self, kernel_id):
        """Interrupt (SIGINT) the kernel by its uuid.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to interrupt.
        """
        km = self.get_kernel(kernel_id)
        await km.interrupt_kernel()
        self.log.info("Kernel interrupted: %s" % kernel_id)

    async def signal_kernel(self, kernel_id, signum):
        """Sends a signal to the kernel by its uuid.

        Note that since only SIGTERM is supported on Windows, this function
        is only useful on Unix systems.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to signal.
        """
        km = self.get_kernel(kernel_id)
        await km.signal_kernel(signum)
        self.log.info("Signaled Kernel %s with %s" % (kernel_id, signum))

    async def restart_kernel(self, kernel_id, now=False):
        """Restart a kernel by its uuid, keeping the same ports.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to interrupt.
        """
        km = self.get_kernel(kernel_id)
        await km.restart_kernel(now)
        self.log.info("Kernel restarted: %s" % kernel_id)

    async def shutdown_all(self, now=False):
        """Shutdown all kernels."""
        kids = self.list_kernel_ids()
        for kid in kids:
            self.request_shutdown(kid)
        for kid in kids:
            await self.finish_shutdown(kid)
            self.cleanup_resources(kid)
            self.remove_kernel(kid)
