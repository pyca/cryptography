from __future__ import print_function

import errno
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from logging import getLogger

try:
    import fcntl
except ImportError:
    fcntl = False
try:
    import Queue
except ImportError:
    import queue as Queue
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
try:
    import unittest2 as unittest
except ImportError:
    import unittest

__version__ = '2.1.1'

logger = getLogger(__name__)

BAD_FD_ERRORS = tuple(getattr(errno, name) for name in ['EBADF', 'EBADFD', 'ENOTCONN'] if hasattr(errno, name))
PY3 = sys.version_info[0] == 3


class BufferingBase(object):
    BUFFSIZE = 8192
    ENCODING = "utf8"

    def __init__(self, fh):
        self.buff = StringIO()
        fd = fh.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        self.fd = fd

    def read(self):
        """
        Read any available data fd. Does NOT block.
        """
        try:
            while 1:
                data = os.read(self.fd, self.BUFFSIZE)
                if not data:
                    break
                try:
                    data = data.decode(self.ENCODING)
                except Exception as exc:
                    logger.exception("%r failed to decode %r: %r", self, data, exc)
                    raise

                self.buff.write(data)
        except OSError as exc:
            if exc.errno not in (
                    errno.EAGAIN, errno.EWOULDBLOCK,
                    errno.EINPROGRESS
            ):
                logger.exception("%r failed to read from FD %s: %r", self, self.fd, exc)
        return self.buff.getvalue()

    def reset(self):
        self.buff = StringIO()

    def cleanup(self):
        pass


class ThreadedBufferingBase(BufferingBase):
    def __init__(self, fh):
        self.buff = StringIO()
        self.fh = fh
        self.thread = threading.Thread(target=self.worker)
        self.thread.start()
        self.queue = Queue.Queue()

    def worker(self):
        while not self.fh.closed:
            try:
                data = self.fh.readline()
                if data:
                    self.queue.put(data)
                else:
                    time.sleep(1)
            except OSError as exc:
                logger.exception("%r failed to read from %s: %r", self, self.fh, exc)
                raise

    def read(self):
        while 1:
            try:
                data = self.queue.get_nowait()
            except Queue.Empty:
                break
            try:
                data = data.decode(self.ENCODING)
            except Exception as exc:
                logger.exception("%r failed to decode %r: %r", self, data, exc)
                raise
            self.buff.write(data)
        return self.buff.getvalue()

    def cleanup(self, ):
        self.thread.join()


class TestProcess(BufferingBase if fcntl else ThreadedBufferingBase):
    __test__ = False

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('env', os.environ)
        kwargs.setdefault('bufsize', 1)
        kwargs.setdefault('universal_newlines', True)
        self.proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=sys.platform != "win32",
            **kwargs
        )
        super(TestProcess, self).__init__(self.proc.stdout)

    @property
    def is_alive(self):
        return self.proc.poll() is None

    def signal(self, sig):
        self.proc.send_signal(sig)

    def __repr__(self):
        return "TestProcess(pid=%s, is_alive=%s)" % (self.proc.pid, self.is_alive)

    def __enter__(self):
        return self

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        try:
            for _ in range(5):
                if self.proc.poll() is not None:
                    return
                time.sleep(0.2)
            for _ in range(5):
                if self.proc.poll() is None:
                    try:
                        self.proc.terminate()
                    except Exception as exc:
                        if exc.errno == errno.ESRCH:
                            return
                        else:
                            logger.exception("%r failed to terminate process: %r", self, exc)
                else:
                    return
                time.sleep(0.2)
            try:
                logger.critical('%s killing unresponsive process!', self)
                self.proc.kill()
            except OSError as exc:
                if exc.errno != errno.ESRCH:
                    raise
        finally:
            try:
                data, _ = self.proc.communicate()
                try:
                    if isinstance(data, bytes):
                        data = data.decode(self.ENCODING)
                except Exception as exc:
                    logger.exception("%s failed to decode %r: %r", self, data, exc)
                    raise
                self.buff.write(data)
            except IOError as exc:
                if exc.errno != errno.EAGAIN:
                    logger.exception('%s failed to cleanup buffers: %r', self, exc)
            except Exception as exc:
                logger.exception('%s failed to cleanup buffers: %r', self, exc)
            try:
                self.cleanup()
            except Exception as exc:
                logger.exception('%s failed to cleanup: %r', self, exc)

    close = __exit__


class TestSocket(BufferingBase if fcntl else ThreadedBufferingBase):
    __test__ = False
    BUFFSIZE = 8192

    def __init__(self, sock):
        self.sock = sock
        if PY3:
            self.fh = sock.makefile('rbw', buffering=1)
        else:
            self.fh = sock.makefile(bufsize=0)

        if fcntl:
            sock.setblocking(0)
            super(TestSocket, self).__init__(sock)
        else:
            super(TestSocket, self).__init__(self.fh)

    def __enter__(self):
        return self

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except (OSError, socket.error) as exc:
            if exc.errno not in BAD_FD_ERRORS:
                raise

    close = __exit__


def wait_for_strings(cb, seconds, *strings):
    """
    This checks that *string appear in cb(), IN THE GIVEN ORDER !
    """
    start = time.time()
    while True:
        buff = cb()
        check_strings = list(strings)
        check_strings.reverse()
        for line in buff.splitlines():
            if not check_strings:
                break
            while check_strings and check_strings[-1] in line:
                check_strings.pop()
        if not check_strings:
            return
        if time.time() - start > seconds:
            break
        time.sleep(0.05)

    raise AssertionError("Waited %0.2fsecs but %s did not appear in output in the given order !" % (
        seconds, check_strings
    ))


@contextmanager
def dump_on_error(cb):
    try:
        yield
    except Exception:
        print("*********** OUTPUT ***********")
        print(cb())
        print("******************************")
        raise


@contextmanager
def dump_always(cb):
    try:
        yield
    finally:
        print("*********** OUTPUT ***********")
        print(cb())
        print("******************************")


class ProcessTestCase(unittest.TestCase):
    dump_on_error = staticmethod(dump_on_error)
    wait_for_strings = staticmethod(wait_for_strings)
