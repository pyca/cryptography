"""A basic in process kernel monitor with autorestarting.

This watches a kernel's state using KernelManager.is_alive and auto
restarts the kernel if it dies.
"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import warnings

from zmq.eventloop import ioloop

from jupyter_client.restarter import KernelRestarter
from traitlets import (
    Instance,
)


class IOLoopKernelRestarter(KernelRestarter):
    """Monitor and autorestart a kernel."""

    loop = Instance('tornado.ioloop.IOLoop')

    def _loop_default(self):
        warnings.warn("IOLoopKernelRestarter.loop is deprecated in jupyter-client 5.2",
            DeprecationWarning, stacklevel=4,
        )
        return ioloop.IOLoop.current()

    _pcallback = None

    def start(self):
        """Start the polling of the kernel."""
        if self._pcallback is None:
            self._pcallback = ioloop.PeriodicCallback(
                self.poll, 1000*self.time_to_dead,
            )
            self._pcallback.start()

    def stop(self):
        """Stop the kernel polling."""
        if self._pcallback is not None:
            self._pcallback.stop()
            self._pcallback = None


class AsyncIOLoopKernelRestarter(IOLoopKernelRestarter):

    async def poll(self):
        if self.debug:
            self.log.debug('Polling kernel...')
        is_alive = await self.kernel_manager.is_alive()
        if not is_alive:
            if self._restarting:
                self._restart_count += 1
            else:
                self._restart_count = 1

            if self._restart_count >= self.restart_limit:
                self.log.warning("AsyncIOLoopKernelRestarter: restart failed")
                self._fire_callbacks('dead')
                self._restarting = False
                self._restart_count = 0
                self.stop()
            else:
                newports = self.random_ports_until_alive and self._initial_startup
                self.log.info('AsyncIOLoopKernelRestarter: restarting kernel (%i/%i), %s random ports',
                    self._restart_count,
                    self.restart_limit,
                    'new' if newports else 'keep'
                )
                self._fire_callbacks('restart')
                await self.kernel_manager.restart_kernel(now=True, newports=newports)
                self._restarting = True
        else:
            if self._initial_startup:
                self._initial_startup = False
            if self._restarting:
                self.log.debug("AsyncIOLoopKernelRestarter: restart apparently succeeded")
            self._restarting = False
