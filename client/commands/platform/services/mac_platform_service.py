import os
import platform
import subprocess
import sys
import time

import psutil


class MacPlatformService:
    """
    macOS 平台能力服务。

    当前先承接两类职责：
    - 系统信息采集
    - AppleScript/osascript 基础能力

    后续可以继续往这里下沉：
    - screenshot / webcam
    - sudo_run / sudo_self
    - volume / notify / msgbox
    """

    def __init__(self, owner):
        self.owner = owner

    def run_command_text(self, command: str, timeout: int = 15) -> str:
        try:
            result = self.owner._run_shell_command(command, timeout=timeout)
            if result.returncode != 0:
                return ''
            return (result.stdout or '').strip()
        except Exception:
            return ''

    def build_process_info(self):
        process = psutil.Process()
        executable_path = os.path.realpath(sys.executable)
        script_path = os.path.realpath(''.join(sys.argv))

        return {
            'hostname': platform.node(),
            'macos_version': platform.mac_ver()[0],
            'build_version': self.run_command_text('sw_vers -buildVersion'),
            'architecture': platform.machine(),
            'hardware_model': self.run_command_text('sysctl -n hw.model'),
            'cpu_brand': self.run_command_text('sysctl -n machdep.cpu.brand_string'),
            'cpu_cores': os.cpu_count(),
            'memory': f'{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB',
            'python_version': platform.python_version(),
            'process_id': os.getpid(),
            'current_user': process.username(),
            'launch_command': f'{executable_path} {script_path}',
            'process_uptime': f'{round(time.time() - process.create_time(), 2)}s',
            'cwd': os.getcwd()
        }

    def escape_osascript_text(self, value: str):
        text = str(value or '')
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        return text

    def spawn_osascript(self, applescript: str):
        process = subprocess.Popen(
            ['osascript', '-e', applescript],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        self.owner._register_cancel_handler(lambda: self.owner._terminate_process(process))
        return process