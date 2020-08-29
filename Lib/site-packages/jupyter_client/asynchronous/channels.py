"""Async channels"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

from queue import Queue, Empty


class ZMQSocketChannel(object):
    """A ZMQ socket in an async API"""
    session = None
    socket = None
    stream = None
    _exiting = False
    proxy_methods = []

    def __init__(self, socket, session, loop=None):
        """Create a channel.

        Parameters
        ----------
        socket : :class:`zmq.asyncio.Socket`
            The ZMQ socket to use.
        session : :class:`session.Session`
            The session to use.
        loop
            Unused here, for other implementations
        """
        super().__init__()

        self.socket = socket
        self.session = session

    async def _recv(self, **kwargs):
        msg = await self.socket.recv_multipart(**kwargs)
        ident,smsg = self.session.feed_identities(msg)
        return self.session.deserialize(smsg)

    async def get_msg(self, timeout=None):
        """ Gets a message if there is one that is ready. """
        if timeout is not None:
            timeout *= 1000  # seconds to ms
        ready = await self.socket.poll(timeout)

        if ready:
            return await self._recv()
        else:
            raise Empty

    async def get_msgs(self):
        """ Get all messages that are currently ready. """
        msgs = []
        while True:
            try:
                msgs.append(await self.get_msg())
            except Empty:
                break
        return msgs

    async def msg_ready(self):
        """ Is there a message that has been received? """
        return bool(await self.socket.poll(timeout=0))

    def close(self):
        if self.socket is not None:
            try:
                self.socket.close(linger=0)
            except Exception:
                pass
            self.socket = None
    stop =  close

    def is_alive(self):
        return (self.socket is not None)

    def send(self, msg):
        """Pass a message to the ZMQ socket to send
        """
        self.session.send(self.socket, msg)

    def start(self):
        pass
