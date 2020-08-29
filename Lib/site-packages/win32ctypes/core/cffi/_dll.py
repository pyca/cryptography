#
# (C) Copyright 2018 Enthought, Inc., Austin, TX
# All right reserved.
#
# This file is open source software distributed according to the terms in
# LICENSE.txt
#
from __future__ import absolute_import

from win32ctypes.core.compat import text_type
from ._util import ffi, check_null, check_false, dlls, HMODULE, PVOID


ffi.cdef("""

HMODULE WINAPI LoadLibraryExW(LPCTSTR lpFileName, HANDLE hFile, DWORD dwFlags);
BOOL WINAPI FreeLibrary(HMODULE hModule);

""")


def _LoadLibraryEx(lpFilename, hFile, dwFlags):
    result = check_null(
        dlls.kernel32.LoadLibraryExW(
            text_type(lpFilename), ffi.NULL, dwFlags),
        function_name='LoadLibraryEx')
    return HMODULE(result)


def _FreeLibrary(hModule):
    check_false(
        dlls.kernel32.FreeLibrary(PVOID(hModule)),
        function_name='FreeLibrary')
