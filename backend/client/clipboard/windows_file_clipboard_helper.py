import ctypes
import os
import struct
import sys


CF_HDROP = 15
GMEM_MOVEABLE = 0x0002
GMEM_ZEROINIT = 0x0040


def _raise_last_error(message):
    error = ctypes.get_last_error()
    if error:
        raise OSError(error, f'{message}: {ctypes.FormatError(error)}')
    raise RuntimeError(message)


def main():
    paths = [os.path.abspath(path) for path in sys.argv[1:] if path]
    if not paths:
        raise ValueError('No clipboard files were provided')

    for path in paths:
        if not os.path.exists(path):
            raise FileNotFoundError(f'Clipboard file does not exist: {path}')

    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    user32.CreateWindowExW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    user32.CreateWindowExW.restype = ctypes.c_void_p
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_int
    user32.EmptyClipboard.restype = ctypes.c_int
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    user32.SetClipboardData.restype = ctypes.c_void_p
    user32.CloseClipboard.restype = ctypes.c_int

    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.restype = ctypes.c_int
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.restype = ctypes.c_void_p

    hwnd = user32.CreateWindowExW(
        0,
        'STATIC',
        'RCH Clipboard File Helper',
        0,
        0,
        0,
        0,
        0,
        None,
        None,
        kernel32.GetModuleHandleW(None),
        None,
    )
    if not hwnd:
        _raise_last_error('Failed to create clipboard owner window')

    file_list = ('\x00'.join(paths) + '\x00\x00').encode('utf-16le')
    dropfiles = struct.pack('<IiiII', 20, 0, 0, 0, 1)
    payload = dropfiles + file_list

    hglobal = kernel32.GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len(payload))
    if not hglobal:
        _raise_last_error('Failed to allocate CF_HDROP memory')

    clipboard_owns_memory = False
    try:
        target = kernel32.GlobalLock(hglobal)
        if not target:
            _raise_last_error('Failed to lock CF_HDROP memory')
        try:
            ctypes.memmove(target, payload, len(payload))
        finally:
            kernel32.GlobalUnlock(hglobal)

        if not user32.OpenClipboard(hwnd):
            _raise_last_error('Failed to open Windows clipboard')
        try:
            if not user32.EmptyClipboard():
                _raise_last_error('Failed to empty Windows clipboard')

            if not user32.SetClipboardData(CF_HDROP, hglobal):
                _raise_last_error('Failed to set CF_HDROP clipboard data')
            clipboard_owns_memory = True
        finally:
            user32.CloseClipboard()
    finally:
        if not clipboard_owns_memory:
            kernel32.GlobalFree(hglobal)


if __name__ == '__main__':
    main()
