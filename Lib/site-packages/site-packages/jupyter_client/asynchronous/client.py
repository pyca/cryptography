"""Implements an async kernel client"""
# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

from functools import partial
from getpass import getpass
from queue import Empty
import sys
import time

import zmq
import zmq.asyncio
import asyncio

from traitlets import (Type, Instance)
from jupyter_client.channels import HBChannel
from jupyter_client.client import KernelClient
from .channels import ZMQSocketChannel


def reqrep(meth, channel='shell'):
    def wrapped(self, *args, **kwargs):
        reply = kwargs.pop('reply', False)
        timeout = kwargs.pop('timeout', None)
        msg_id = meth(self, *args, **kwargs)
        if not reply:
            return msg_id

        return self._recv_reply(msg_id, timeout=timeout, channel=channel)

    if not meth.__doc__:
        # python -OO removes docstrings,
        # so don't bother building the wrapped docstring
        return wrapped

    basedoc, _ = meth.__doc__.split('Returns\n', 1)
    parts = [basedoc.strip()]
    if 'Parameters' not in basedoc:
        parts.append("""
        Parameters
        ----------
        """)
    parts.append("""
        reply: bool (default: False)
            Whether to wait for and return reply
        timeout: float or None (default: None)
            Timeout to use when waiting for a reply

        Returns
        -------
        msg_id: str
            The msg_id of the request sent, if reply=False (default)
        reply: dict
            The reply message for this request, if reply=True
    """)
    wrapped.__doc__ = '\n'.join(parts)
    return wrapped

class AsyncKernelClient(KernelClient):
    """A KernelClient with async APIs

    ``get_[channel]_msg()`` methods wait for and return messages on channels,
    raising :exc:`queue.Empty` if no message arrives within ``timeout`` seconds.
    """

    # The PyZMQ Context to use for communication with the kernel.
    context = Instance(zmq.asyncio.Context)
    def _context_default(self):
        return zmq.asyncio.Context()

    #--------------------------------------------------------------------------
    # Channel proxy methods
    #--------------------------------------------------------------------------

    async def get_shell_msg(self, *args, **kwargs):
        """Get a message from the shell channel"""
        return await self.shell_channel.get_msg(*args, **kwargs)

    async def get_iopub_msg(self, *args, **kwargs):
        """Get a message from the iopub channel"""
        return await self.iopub_channel.get_msg(*args, **kwargs)

    async def get_stdin_msg(self, *args, **kwargs):
        """Get a message from the stdin channel"""
        return await self.stdin_channel.get_msg(*args, **kwargs)

    async def get_control_msg(self, *args, **kwargs):
        """Get a message from the control channel"""
        return await self.control_channel.get_msg(*args, **kwargs)

    @property
    def hb_channel(self):
        """Get the hb channel object for this kernel."""
        if self._hb_channel is None:
            url = self._make_url('hb')
            self.log.debug("connecting heartbeat channel to %s", url)
            loop = asyncio.new_event_loop()
            self._hb_channel = self.hb_channel_class(
                self.context, self.session, url, loop
            )
        return self._hb_channel

    async def wait_for_ready(self, timeout=None):
        """Waits for a response when a client is blocked

        - Sets future time for timeout
        - Blocks on shell channel until a message is received
        - Exit if the kernel has died
        - If client times out before receiving a message from the kernel, send RuntimeError
        - Flush the IOPub channel
        """
        if timeout is None:
            abs_timeout = float('inf')
        else:
            abs_timeout = time.time() + timeout

        from ..manager import KernelManager
        if not isinstance(self.parent, KernelManager):
            # This Client was not created by a KernelManager,
            # so wait for kernel to become responsive to heartbeats
            # before checking for kernel_info reply
            while not self.is_alive():
                if time.time() > abs_timeout:
                    raise RuntimeError("Kernel didn't respond to heartbeats in %d seconds and timed out" % timeout)
                await asyncio.sleep(0.2)

        # Wait for kernel info reply on shell channel
        while True:
            try:
                msg = await self.shell_channel.get_msg(timeout=1)
            except Empty:
                pass
            else:
                if msg['msg_type'] == 'kernel_info_reply':
                    self._handle_kernel_info_reply(msg)
                    break

            if not await self.is_alive():
                raise RuntimeError('Kernel died before replying to kernel_info')

            # Check if current time is ready check time plus timeout
            if time.time() > abs_timeout:
                raise RuntimeError("Kernel didn't respond in %d seconds" % timeout)

        # Flush IOPub channel
        while True:
            try:
                msg = await self.iopub_channel.get_msg(timeout=0.2)
            except Empty:
                break

    # The classes to use for the various channels
    shell_channel_class = Type(ZMQSocketChannel)
    iopub_channel_class = Type(ZMQSocketChannel)
    stdin_channel_class = Type(ZMQSocketChannel)
    hb_channel_class = Type(HBChannel)
    control_channel_class = Type(ZMQSocketChannel)


    async def _recv_reply(self, msg_id, timeout=None, channel='shell'):
        """Receive and return the reply for a given request"""
        if timeout is not None:
            deadline = time.monotonic() + timeout
        while True:
            if timeout is not None:
                timeout = max(0, deadline - time.monotonic())
            try:
                if channel == 'control':
                    reply = await self.get_control_msg(timeout=timeout)
                else:
                    reply = await self.get_shell_msg(timeout=timeout)
            except Empty as e:
                raise TimeoutError("Timeout waiting for reply") from e
            if reply['parent_header'].get('msg_id') != msg_id:
                # not my reply, someone may have forgotten to retrieve theirs
                continue
            return reply


    # replies come on the shell channel
    execute = reqrep(KernelClient.execute)
    history = reqrep(KernelClient.history)
    complete = reqrep(KernelClient.complete)
    inspect = reqrep(KernelClient.inspect)
    kernel_info = reqrep(KernelClient.kernel_info)
    comm_info = reqrep(KernelClient.comm_info)

    # replies come on the control channel
    shutdown = reqrep(KernelClient.shutdown, channel='control')


    def _stdin_hook_default(self, msg):
        """Handle an input request"""
        content = msg['content']
        if content.get('password', False):
            prompt = getpass
        else:
            prompt = input

        try:
            raw_data = prompt(content["prompt"])
        except EOFError:
            # turn EOFError into EOF character
            raw_data = '\x04'
        except KeyboardInterrupt:
            sys.stdout.write('\n')
            return

        # only send stdin reply if there *was not* another request
        # or execution finished while we were reading.
        if not (self.stdin_channel.msg_ready() or self.shell_channel.msg_ready()):
            self.input(raw_data)

    def _output_hook_default(self, msg):
        """Default hook for redisplaying plain-text output"""
        msg_type = msg['header']['msg_type']
        content = msg['content']
        if msg_type == 'stream':
            stream = getattr(sys, content['name'])
            stream.write(content['text'])
        elif msg_type in ('display_data', 'execute_result'):
            sys.stdout.write(content['data'].get('text/plain', ''))
        elif msg_type == 'error':
            print('\n'.join(content['traceback']), file=sys.stderr)

    def _output_hook_kernel(self, session, socket, parent_header, msg):
        """Output hook when running inside an IPython kernel

        adds rich output support.
        """
        msg_type = msg['header']['msg_type']
        if msg_type in ('display_data', 'execute_result', 'error'):
            session.send(socket, msg_type, msg['content'], parent=parent_header)
        else:
            self._output_hook_default(msg)

    async def is_alive(self):
        """Is the kernel process still running?"""
        from ..manager import KernelManager, AsyncKernelManager
        if isinstance(self.parent, KernelManager):
            # This KernelClient was created by a KernelManager,
            # we can ask the parent KernelManager:
            if isinstance(self.parent, AsyncKernelManager):
                return await self.parent.is_alive()
            return self.parent.is_alive()
        if self._hb_channel is not None:
            # We don't have access to the KernelManager,
            # so we use the heartbeat.
            return self._hb_channel.is_beating()
        else:
            # no heartbeat and not local, we can't tell if it's running,
            # so naively return True
            return True

    async def execute_interactive(self, code, silent=False, store_history=True,
                 user_expressions=None, allow_stdin=None, stop_on_error=True,
                 timeout=None, output_hook=None, stdin_hook=None,
                ):
        """Execute code in the kernel interactively

        Output will be redisplayed, and stdin prompts will be relayed as well.
        If an IPython kernel is detected, rich output will be displayed.

        You can pass a custom output_hook callable that will be called
        with every IOPub message that is produced instead of the default redisplay.

        Parameters
        ----------
        code : str
            A string of code in the kernel's language.

        silent : bool, optional (default False)
            If set, the kernel will execute the code as quietly possible, and
            will force store_history to be False.

        store_history : bool, optional (default True)
            If set, the kernel will store command history.  This is forced
            to be False if silent is True.

        user_expressions : dict, optional
            A dict mapping names to expressions to be evaluated in the user's
            dict. The expression values are returned as strings formatted using
            :func:`repr`.

        allow_stdin : bool, optional (default self.allow_stdin)
            Flag for whether the kernel can send stdin requests to frontends.

            Some frontends (e.g. the Notebook) do not support stdin requests.
            If raw_input is called from code executed from such a frontend, a
            StdinNotImplementedError will be raised.

        stop_on_error: bool, optional (default True)
            Flag whether to abort the execution queue, if an exception is encountered.

        timeout: float or None (default: None)
            Timeout to use when waiting for a reply

        output_hook: callable(msg)
            Function to be called with output messages.
            If not specified, output will be redisplayed.

        stdin_hook: callable(msg)
            Function to be called with stdin_request messages.
            If not specified, input/getpass will be called.

        Returns
        -------
        reply: dict
            The reply message for this request
        """
        if not self.iopub_channel.is_alive():
            raise RuntimeError("IOPub channel must be running to receive output")
        if allow_stdin is None:
            allow_stdin = self.allow_stdin
        if allow_stdin and not self.stdin_channel.is_alive():
            raise RuntimeError("stdin channel must be running to allow input")
        msg_id = await self.execute(code,
                              silent=silent,
                              store_history=store_history,
                              user_expressions=user_expressions,
                              allow_stdin=allow_stdin,
                              stop_on_error=stop_on_error,
        )
        if stdin_hook is None:
            stdin_hook = self._stdin_hook_default
        if output_hook is None:
            # detect IPython kernel
            if 'IPython' in sys.modules:
                from IPython import get_ipython
                ip = get_ipython()
                in_kernel = getattr(ip, 'kernel', False)
                if in_kernel:
                    output_hook = partial(
                        self._output_hook_kernel,
                        ip.display_pub.session,
                        ip.display_pub.pub_socket,
                        ip.display_pub.parent_header,
                    )
        if output_hook is None:
            # default: redisplay plain-text outputs
            output_hook = self._output_hook_default

        # set deadline based on timeout
        if timeout is not None:
            deadline = time.monotonic() + timeout
        else:
            timeout_ms = None

        poller = zmq.Poller()
        iopub_socket = self.iopub_channel.socket
        poller.register(iopub_socket, zmq.POLLIN)
        if allow_stdin:
            stdin_socket = self.stdin_channel.socket
            poller.register(stdin_socket, zmq.POLLIN)
        else:
            stdin_socket = None

        # wait for output and redisplay it
        while True:
            if timeout is not None:
                timeout = max(0, deadline - time.monotonic())
                timeout_ms = 1e3 * timeout
            events = dict(poller.poll(timeout_ms))
            if not events:
                raise TimeoutError("Timeout waiting for output")
            if stdin_socket in events:
                req = await self.stdin_channel.get_msg(timeout=0)
                stdin_hook(req)
                continue
            if iopub_socket not in events:
                continue

            msg = await self.iopub_channel.get_msg(timeout=0)

            if msg['parent_header'].get('msg_id') != msg_id:
                # not from my request
                continue
            output_hook(msg)

            # stop on idle
            if msg['header']['msg_type'] == 'status' and \
            msg['content']['execution_state'] == 'idle':
                break

        # output is done, get the reply
        if timeout is not None:
            timeout = max(0, deadline - time.monotonic())
        return await self._recv_reply(msg_id, timeout=timeout)
