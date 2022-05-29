import ctypes
import os
import pathlib
import threading
import time

import pywintypes
import win32con
import win32file

FILE_CREATED = 1
FILE_DELETED = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5


class FileWatch:

    def __init__(self):
        self.handle_directory = None
        self.stop = threading.Event()

    @staticmethod
    def get_time():
        return str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, 'instance'):
            setattr(cls, 'instance', cls())
        return getattr(cls, 'instance')

    def monitor(self, path, func, eof):
        self.handle_directory = win32file.CreateFile(
            path,
            0x0001,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None)
        while not self.stop.is_set():
            try:
                results = win32file.ReadDirectoryChangesW(
                    self.handle_directory,
                    1024,
                    True,
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                    win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                    win32con.FILE_NOTIFY_CHANGE_SIZE,
                    None, None
                )
                if self.stop.is_set():
                    func('[*] Exiting...')
                    eof()
                    break
                for action, filename in results:
                    filename = os.path.join(path, filename)
                    if action == FILE_CREATED:
                        func('[+] {} Created {}'.format(self.get_time(), filename))
                    elif action == FILE_DELETED:
                        func('[+] {} Deleted {}'.format(self.get_time(), filename))
                    elif action == FILE_MODIFIED:
                        func('[+] {} Modified {}'.format(self.get_time(), filename))
                        file_size = os.stat(filename).st_size
                        if os.path.isfile(filename) and pathlib.Path(filename).suffix == '.txt' and file_size < 1024:
                            func('[*] Dumping contents of {} ({} Bytes)...'.format(filename, file_size))
                            with open(filename, 'r', encoding='utf-8') as f:
                                data = f.read()
                            func(data)
                            func('[+] Dump completed')
                    elif action == FILE_RENAMED_FROM:
                        func('[+] {} Renamed from {}'.format(self.get_time(), filename))
                    elif action == FILE_RENAMED_TO:
                        func('[+] {} Renamed to {}'.format(self.get_time(), filename))
                    else:
                        func('[+] {} Unknown {}'.format(self.get_time(), filename))
            except pywintypes.error:
                func('[*] Exiting...')
                eof()
                break
            except Exception as e:
                func('[-] {} Error: {}'.format(self.get_time(), e))

    def start_monitor(self, path, func, eof):
        self.stop.clear()
        func('Start monitoring: {}'.format(path))
        threading.Thread(target=self.monitor, args=(path, func, eof,), daemon=True).start()

    def stop_monitor(self):
        self.stop.set()
        ctypes.windll.kernel32.CancelIoEx(int(self.handle_directory), None)
        win32file.CloseHandle(self.handle_directory)
