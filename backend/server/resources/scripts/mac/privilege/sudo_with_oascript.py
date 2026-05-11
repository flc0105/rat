SCRIPT_METADATA = {
    "name": "mac/sudo/sudo_with_oascript",
    "display_name": "Elevate to Administrator",
    "description": "Launch a new client session with administrator privileges via AppleScript password prompt",
    "platforms": ["macos"],
    "category": "System",
    "params": []
}

import subprocess

from client.runtime.client_util import get_executable_path


def sudo_with_osascript(command):
    script = f'''
    do shell script "{command}" with administrator privileges
    '''
    print(script)
    result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True)
    return result


sudo_with_osascript(get_executable_path())
