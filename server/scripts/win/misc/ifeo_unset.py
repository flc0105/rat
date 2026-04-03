import winreg
import ctypes


def remove_startup_intercept(intercept_target):
    try:
        if not intercept_target:
            print('[-] Missing intercepted target executable name')
            return

        if not ctypes.windll.shell32.IsUserAnAdmin():
            print('[-] Administrator privileges are required')
            return

        reg_path = (
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}'
            .format(intercept_target)
        )

        # 打开键
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            reg_path,
            0,
            winreg.KEY_SET_VALUE
        )

        try:
            # 删除 Debugger 值
            winreg.DeleteValue(key, 'Debugger')
            print('[+] Debugger value removed')
        except FileNotFoundError:
            print('[!] Debugger value not found')

        winreg.CloseKey(key)

        print('[+] Startup intercept removed successfully')
        print('[+] Target restored: {}'.format(intercept_target))

    except FileNotFoundError:
        print('[!] Registry key not found (already clean)')
    except Exception as error:
        print('[-] Failed to remove intercept: {}'.format(error))


intercept_target = kwargs.get('intercept', '')
remove_startup_intercept(intercept_target)