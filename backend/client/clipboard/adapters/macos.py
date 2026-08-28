import io
import os

from PIL import Image


class MacOSClipboardAdapter:
    def _imports(self):
        from AppKit import NSPasteboard, NSPasteboardTypePNG, NSPasteboardTypeString, NSPasteboardTypeTIFF
        from Foundation import NSData, NSURL
        try:
            from AppKit import NSPasteboardURLReadingFileURLsOnlyKey
        except ImportError:
            NSPasteboardURLReadingFileURLsOnlyKey = 'NSPasteboardURLReadingFileURLsOnlyKey'
        return (
            NSPasteboard,
            NSPasteboardTypePNG,
            NSPasteboardTypeString,
            NSPasteboardTypeTIFF,
            NSPasteboardURLReadingFileURLsOnlyKey,
            NSData,
            NSURL,
        )

    def get_capabilities(self) -> dict:
        try:
            self._imports()
            return {'text': True, 'image': True, 'files': True}
        except Exception:
            return {'text': False, 'image': False, 'files': False}

    def get_snapshot(self) -> dict:
        (
            NSPasteboard,
            NSPasteboardTypePNG,
            NSPasteboardTypeString,
            NSPasteboardTypeTIFF,
            NSPasteboardURLReadingFileURLsOnlyKey,
            _,
            NSURL,
        ) = self._imports()
        pasteboard = NSPasteboard.generalPasteboard()

        urls = pasteboard.readObjectsForClasses_options_(
            [NSURL],
            {NSPasteboardURLReadingFileURLsOnlyKey: True},
        ) or []
        paths = []
        for url in urls:
            try:
                path = str(url.path() or '')
            except Exception:
                path = ''
            if path and os.path.exists(path):
                paths.append(path)
        if paths:
            return {'kind': 'files', 'paths': paths}

        data = pasteboard.dataForType_(NSPasteboardTypePNG)
        image_format = 'png'
        if data is None:
            data = pasteboard.dataForType_(NSPasteboardTypeTIFF)
            image_format = 'tiff'
        if data is not None:
            return {'kind': 'image', 'data': bytes(data), 'format': image_format}

        text = pasteboard.stringForType_(NSPasteboardTypeString)
        if text is not None:
            return {'kind': 'text', 'text': str(text)}

        return {'kind': 'empty'}

    def set_text(self, text: str):
        NSPasteboard, _, NSPasteboardTypeString, _, _, _, _ = self._imports()
        pasteboard = NSPasteboard.generalPasteboard()
        pasteboard.clearContents()
        if not pasteboard.setString_forType_(str(text or ''), NSPasteboardTypeString):
            raise RuntimeError('Failed to write text to macOS clipboard')

    def set_image(self, image_path: str):
        NSPasteboard, NSPasteboardTypePNG, _, _, _, NSData, _ = self._imports()
        image = Image.open(image_path)
        output = io.BytesIO()
        image.save(output, format='PNG')
        raw = output.getvalue()
        data = NSData.dataWithBytes_length_(raw, len(raw))
        pasteboard = NSPasteboard.generalPasteboard()
        pasteboard.clearContents()
        if not pasteboard.setData_forType_(data, NSPasteboardTypePNG):
            raise RuntimeError('Failed to write image to macOS clipboard')

    def set_files(self, paths: list[str]):
        NSPasteboard, _, _, _, _, _, NSURL = self._imports()
        urls = [NSURL.fileURLWithPath_(os.path.abspath(path)) for path in paths if path]
        if not urls:
            raise ValueError('No clipboard files were provided')
        pasteboard = NSPasteboard.generalPasteboard()
        pasteboard.clearContents()
        if not pasteboard.writeObjects_(urls):
            raise RuntimeError('Failed to write file URLs to macOS clipboard')
