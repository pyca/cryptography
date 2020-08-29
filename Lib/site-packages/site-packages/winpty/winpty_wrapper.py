# -*- coding: utf-8 -*-
"""Wrap process I/O pipe communication using pywin32."""

# yapf: disable

# Standard library imports
from ctypes import windll
from ctypes.wintypes import DWORD, LPVOID, HANDLE, BOOL, LPCVOID
import ctypes

# Local imports
from .cywinpty import Agent

import sys

PY2 = sys.version_info[0] == 2

# yapf: enable

OPEN_EXISTING = 3
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

LARGE_INTEGER = ctypes.c_ulong
PLARGE_INTEGER = ctypes.POINTER(LARGE_INTEGER)
LPOVERLAPPED = LPVOID

# LPDWORD is not in ctypes.wintypes on Python 2
LPDWORD = ctypes.POINTER(DWORD)

ReadFile = windll.kernel32.ReadFile
ReadFile.restype = BOOL
ReadFile.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED]

WriteFile = windll.kernel32.WriteFile
WriteFile.restype = BOOL
WriteFile.argtypes = [HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED]


class PTY(Agent):
    """
    This class provides a pywin32 communication wrapper around winpty process
    communication pipes.

    Inherits all Cython winpty agent functionality and properties.
    """

    def __init__(self, cols, rows):
        """Initialize a new Pseudo Terminal of size ``(cols, rows)``."""
        Agent.__init__(self, cols, rows, True)
        self.conin_pipe = windll.kernel32.CreateFileW(
            self.conin_pipe_name, GENERIC_WRITE, 0, None, OPEN_EXISTING, 0,
            None
        )
        self.conout_pipe = windll.kernel32.CreateFileW(
            self.conout_pipe_name, GENERIC_READ, 0, None, OPEN_EXISTING, 0,
            None
        )

    def read(self, length=1000, blocking=False):
        """
        Read ``length`` bytes from current process output stream.

        Note: This method is not fully non-blocking, however it
        behaves like one.
        """
        size_p = PLARGE_INTEGER(LARGE_INTEGER(0))
        if not blocking:
            windll.kernel32.GetFileSizeEx(self.conout_pipe, size_p)
            size = size_p[0]
            length = min(size, length)
        data = ctypes.create_string_buffer(length)
        if length > 0:
            num_bytes = PLARGE_INTEGER(LARGE_INTEGER(0))
            ReadFile(self.conout_pipe, data, length, num_bytes, None)
        return data.value

    def write(self, data):
        """Write string data to current process input stream."""
        data = data.encode('utf-8')
        data_p = ctypes.create_string_buffer(data)
        num_bytes = PLARGE_INTEGER(LARGE_INTEGER(0))
        bytes_to_write = len(data)
        success = WriteFile(self.conin_pipe, data_p,
                            bytes_to_write, num_bytes, None)
        return success, num_bytes[0]

    def close(self):
        """Close all communication process streams."""
        windll.kernel32.CloseHandle(self.conout_pipe)
        windll.kernel32.CloseHandle(self.conin_pipe)

    def iseof(self):
        """Check if current process streams are still open."""
        succ = windll.kernel32.PeekNamedPipe(
            self.conout_pipe, None, None, None, None, None
        )
        return not bool(succ)
