import subprocess

from core.utils.client_util import get_executable_path


def sudo_with_osascript(command):
    """通过 AppleScript 弹窗输入密码"""
    script = f'''
    do shell script "{command}" with administrator privileges
    '''
    print(script)
    result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True)
    return result


sudo_with_osascript(get_executable_path())
