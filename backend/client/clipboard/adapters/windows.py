import io
import os
from contextlib import contextmanager

from PIL import Image


class WindowsClipboardAdapter:
    def get_capabilities(self) -> dict:
        return {'text': True, 'image': True, 'files': True}

    def _imports(self):
        import win32api
        import win32clipboard
        import win32con
        import win32gui
        return win32api, win32clipboard, win32con, win32gui

    def get_snapshot(self) -> dict:
        _, win32clipboard, win32con, _ = self._imports()
        win32clipboard.OpenClipboard()
        try:
            if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                paths = [str(item) for item in (win32clipboard.GetClipboardData(win32con.CF_HDROP) or [])]
                paths = [path for path in paths if path and os.path.exists(path)]
                if paths:
                    return {'kind': 'files', 'paths': paths}

            if win32clipboard.IsClipboardFormatAvailable(win32con.CF_DIB):
                dib = win32clipboard.GetClipboardData(win32con.CF_DIB)
                if dib:
                    bmp_header = self._build_bmp_header(dib)
                    image = Image.open(io.BytesIO(bmp_header + dib))
                    output = io.BytesIO()
                    image.save(output, format='PNG')
                    return {
                        'kind': 'image',
                        'data': output.getvalue(),
                        'format': 'png',
                        'width': int(image.width),
                        'height': int(image.height),
                    }

            if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                return {'kind': 'text', 'text': str(text or '')}

            return {'kind': 'empty'}
        finally:
            win32clipboard.CloseClipboard()

    def set_text(self, text: str):
        with self._open_clipboard_for_write() as (win32clipboard, win32con):
            win32clipboard.SetClipboardText(
                str(text or ''),
                win32con.CF_UNICODETEXT,
            )

    def set_image(self, image_path: str):
        image = Image.open(image_path).convert('RGB')
        output = io.BytesIO()
        image.save(output, format='BMP')
        dib = output.getvalue()[14:]

        with self._open_clipboard_for_write() as (win32clipboard, win32con):
            win32clipboard.SetClipboardData(win32con.CF_DIB, dib)

    def set_files(self, paths: list[str]):
        normalized = [os.path.abspath(path) for path in paths if path]
        if not normalized:
            raise ValueError('No clipboard files were provided')

        payload = ('\x00'.join(normalized) + '\x00\x00').encode('utf-16le')
        # DROPFILES: pFiles=20, pt=(0,0), fNC=0, fWide=1.
        header = (20).to_bytes(4, 'little') + (0).to_bytes(4, 'little') * 3 + (1).to_bytes(4, 'little')

        with self._open_clipboard_for_write() as (win32clipboard, win32con):
            win32clipboard.SetClipboardData(win32con.CF_HDROP, header + payload)

    @contextmanager
    def _open_clipboard_for_write(self):
        win32api, win32clipboard, win32con, win32gui = self._imports()

        # EmptyClipboard 后 SetClipboardData 需要一个真实 HWND 作为 clipboard owner。
        owner_hwnd = win32gui.CreateWindowEx(
            0,
            'STATIC',
            'RCH Clipboard Owner',
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            win32api.GetModuleHandle(None),
            None,
        )

        try:
            win32clipboard.OpenClipboard(owner_hwnd)
            try:
                win32clipboard.EmptyClipboard()
                yield win32clipboard, win32con
            finally:
                win32clipboard.CloseClipboard()
        finally:
            win32gui.DestroyWindow(owner_hwnd)

    @staticmethod
    def _build_bmp_header(dib: bytes) -> bytes:
        header_size = int.from_bytes(dib[0:4], 'little') if len(dib) >= 4 else 40
        bit_count = int.from_bytes(dib[14:16], 'little') if len(dib) >= 16 else 24
        colors_used = int.from_bytes(dib[32:36], 'little') if len(dib) >= 36 else 0
        if colors_used:
            color_table_size = colors_used * 4
        elif bit_count <= 8:
            color_table_size = (1 << bit_count) * 4
        else:
            color_table_size = 0
        pixel_offset = 14 + header_size + color_table_size
        file_size = 14 + len(dib)
        return (
            b'BM'
            + file_size.to_bytes(4, 'little')
            + b'\x00\x00\x00\x00'
            + pixel_offset.to_bytes(4, 'little')
        )
