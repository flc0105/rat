import io
import os

from PIL import Image


class WindowsClipboardAdapter:
    def get_capabilities(self) -> dict:
        return {'text': True, 'image': True, 'files': True}

    def _imports(self):
        import win32clipboard
        import win32con
        return win32clipboard, win32con

    def get_snapshot(self) -> dict:
        win32clipboard, win32con = self._imports()
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
        win32clipboard, win32con = self._imports()
        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, str(text or ''))
        finally:
            win32clipboard.CloseClipboard()

    def set_image(self, image_path: str):
        win32clipboard, win32con = self._imports()
        image = Image.open(image_path).convert('RGB')
        output = io.BytesIO()
        image.save(output, format='BMP')
        dib = output.getvalue()[14:]

        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32con.CF_DIB, dib)
        finally:
            win32clipboard.CloseClipboard()

    def set_files(self, paths: list[str]):
        win32clipboard, win32con = self._imports()
        normalized = [os.path.abspath(path) for path in paths if path]
        if not normalized:
            raise ValueError('No clipboard files were provided')

        payload = ('\x00'.join(normalized) + '\x00\x00').encode('utf-16le')
        # DROPFILES: pFiles=20, pt=(0,0), fNC=0, fWide=1.
        header = (20).to_bytes(4, 'little') + (0).to_bytes(4, 'little') * 3 + (1).to_bytes(4, 'little')

        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32con.CF_HDROP, header + payload)
        finally:
            win32clipboard.CloseClipboard()

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
