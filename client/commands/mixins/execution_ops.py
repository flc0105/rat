import os
import subprocess
import sys
import time

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.interrupts import interruptible, cancel_policy, timeout
from client.commands.services.process_execution_service import ProcessExecutionService
from client.commands.services.python_execution_service import PythonExecutionService
from client.config.runtime_config import (
    COMMAND_DEFAULT_SHELL_TIMEOUT,
    COMMAND_DEFAULT_STREAM_TIMEOUT,
    COMMAND_PROCESS_WAIT_POLL_INTERVAL,
)
from core.utils.decorator import desc


class CommandExecutionMixin:
    DEFAULT_SHELL_TIMEOUT = COMMAND_DEFAULT_SHELL_TIMEOUT
    DEFAULT_STREAM_TIMEOUT = COMMAND_DEFAULT_STREAM_TIMEOUT
    PROCESS_KILL_GRACE_SECONDS = 2
    PROCESS_WAIT_POLL_INTERVAL = COMMAND_PROCESS_WAIT_POLL_INTERVAL

    def __init__(self, *args, **kwargs):
        self._process_execution_service = None
        self._python_execution_service = None
        super().__init__(*args, **kwargs)

    # ------------------ 通用输出/子进程工具 ------------------ #
    def _get_process_execution_service(self) -> ProcessExecutionService:
        if self._process_execution_service is None:
            self._process_execution_service = ProcessExecutionService(self)
        return self._process_execution_service

    def _get_python_execution_service(self) -> PythonExecutionService:
        if self._python_execution_service is None:
            self._python_execution_service = PythonExecutionService(
                self,
                self._get_process_execution_service()
            )
        return self._python_execution_service

    def _get_default_encoding(self):
        """
        获取系统默认编码
        """
        return self._get_process_execution_service().get_default_encoding()

    def _stream_process_output(self, stream, status=1):
        """
        持续读取子进程输出流并发送中间结果
        """
        return self._get_process_execution_service().stream_process_output(
            stream,
            status=status,
            timeout=self.DEFAULT_STREAM_TIMEOUT,
        )

    def _build_process_creation_kwargs(self) -> dict:
        """
        构造可被强制终止的一组子进程创建参数
        """
        return self._get_process_execution_service().build_process_creation_kwargs()

    def _terminate_process(self, process: subprocess.Popen):
        """
        终止子进程；优先杀整个进程组
        """
        return self._get_process_execution_service().terminate_process(process)

    def _wait_process_with_cancel_support(self, process: subprocess.Popen, timeout=None):
        return self._get_process_execution_service().wait_process_with_cancel_support(
            process,
            timeout=timeout,
        )

    def _run_shell_command(self, command, timeout=None):
        """
        执行一次性 shell 命令
        """
        return self._get_process_execution_service().run_shell_command(
            command,
            timeout=timeout,
        )

    def _start_stream_process(self, command):
        """
        启动带流式输出的子进程
        """
        return self._get_process_execution_service().start_stream_process(command)

    def _start_output_threads(self, process):
        """
        为 stdout/stderr 启动输出读取线程
        """
        return self._get_process_execution_service().start_output_threads(process)

    def _wait_stream_process(self, process, timeout=None):
        """
        等待流式子进程结束；超时则强制终止
        """
        effective_timeout = self.DEFAULT_STREAM_TIMEOUT if timeout is None else timeout
        return self._get_process_execution_service().wait_stream_process(
            process,
            timeout=effective_timeout,
        )

    def _build_restart_command(self):
        """
        构造当前程序重启命令
        """
        from core.utils.client_util import get_executable_path
        return get_executable_path()

    def _spawn_background_process(self, command: str):
        """
        启动后台进程并立即返回
        """
        return self._get_process_execution_service().spawn_background_process(command)

    # ------------------ 基础命令 ------------------ #
    @desc('Change working directory', group='shell')
    @interruptible()
    def cd(self, path):
        try:
            os.chdir(path)
            return 1, ""
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to change directory: {e}'

    @desc('Run a shell command', group='shell')
    @interruptible()
    def shell(self, command):
        try:
            result = self._run_shell_command(command)
            if result.returncode == 0:
                return 1, result.stdout
            return 0, result.stderr or f'Command exited with code {result.returncode}'
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except (CommandTimeoutError, subprocess.TimeoutExpired):
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to execute command: {e}'

    @desc('Run a program in background', group='shell')
    @interruptible()
    def spawn(self, command):
        """
        后台启动指定程序/命令，不等待其执行结束。
        """
        command_text = (command or '').strip()
        if not command_text:
            return 0, 'Usage: spawn <program ...>'

        try:
            process = self._spawn_background_process(command_text)
            return 1, (
                f'Background process started\n'
                f'PID: {process.pid}\n'
                f'Command: {command_text}'
            )
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to start background process: {e}'

    @desc('Run a command with live output', group='shell')
    @interruptible()
    def read(self, command):
        try:
            process = self._start_stream_process(command)
            self._start_output_threads(process)
            self._wait_stream_process(process)
            time.sleep(0.1)

            if process.returncode == 0:
                self._send_final_result(1, "Command completed")
            else:
                self._send_final_result(0, f'Command exited with code {process.returncode}')
        except CommandCancelledError:
            self._send_final_result(0, 'Command cancelled')
        except (CommandTimeoutError, subprocess.TimeoutExpired):
            self._send_final_result(0, 'Command timed out and was terminated')
        except Exception as e:
            self._send_final_result(0, f'Failed to execute command: {e}')

    @desc('Execute Python code', group='shell')
    @interruptible()
    @cancel_policy(True)
    def pyexec(self, code, kwargs=None):
        """
        以可取消子进程模式执行 Python 代码，并在结束后汇总输出。
        """
        try:
            status, output = self._get_python_execution_service().execute_collect(
                code,
                kwargs=kwargs,
                timeout=self._resolve_timeout(self.DEFAULT_STREAM_TIMEOUT),
            )
            return status, output
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except (CommandTimeoutError, subprocess.TimeoutExpired):
            return 0, 'Command timed out'
        except Exception as e:
            return 0, f'Failed to execute code: {e}'

    @desc('Execute Python code with streaming output (generator)', group='shell')
    @interruptible()
    @cancel_policy(True)
    def pyexec_gen(self, code, kwargs=None):
        """
        执行 Python 代码并生成输出流。
        现在统一复用可取消的子进程执行模型，避免和 pyexec / script 链路分叉。
        """
        try:
            self._get_python_execution_service().execute_stream(
                code,
                kwargs=kwargs,
                timeout=self._resolve_timeout(self.DEFAULT_STREAM_TIMEOUT),
            )
        except CommandCancelledError:
            self._send_final_result(0, 'Command cancelled')
        except (CommandTimeoutError, subprocess.TimeoutExpired):
            self._send_final_result(0, 'Command timed out')
        except Exception as e:
            self._send_final_result(0, f'Failed to execute code: {e}')

    @desc('Execute Python code in subprocess with streaming output', group='shell')
    @interruptible()
    @cancel_policy(True)
    def pyexec_subprocess_gen(self, code, kwargs=None):
        """
        在子进程中执行 Python 代码，实时流式输出，支持强制取消。
        兼容保留原有命令名，内部统一走同一套 PythonExecutionService。
        """
        try:
            self._get_python_execution_service().execute_stream(
                code,
                kwargs=kwargs,
                timeout=self._resolve_timeout(self.DEFAULT_STREAM_TIMEOUT),
            )
        except CommandCancelledError:
            self._send_final_result(0, 'Command cancelled')
        except (CommandTimeoutError, subprocess.TimeoutExpired):
            self._send_final_result(0, 'Command timed out')
        except Exception as e:
            self._send_final_result(0, f'Failed to execute code: {e}')

    # ------------------ 连接控制 ------------------ #
    @desc('Terminate current session', group='session')
    @interruptible()
    def kill(self):
        self.socket.close()
        sys.exit(0)

    @desc('Restart client process and reconnect', group='session')
    @interruptible()
    def reset(self):
        restart_command = self._build_restart_command()
        if os.name == 'nt':
            subprocess.Popen(restart_command)
        elif os.name == 'posix':
            subprocess.Popen(restart_command, shell=True)
        self.socket.close()
        sys.exit(0)

    @desc('Get current user ID/name', group='system')
    @interruptible()
    def getuid(self):
        """获取当前用户名"""
        import getpass
        return 1, getpass.getuser()

    @desc('Print working directory', group='system')
    @interruptible()
    def pwd(self):
        """显示当前工作目录"""
        return 1, os.getcwd()

    @desc('Simulate keyboard input', group='system')
    @interruptible()
    def keyboard_send(self, text):
        """模拟键盘输入文字"""
        try:
            import pyautogui
            pyautogui.write(text)
            return 1, f'Typed: {text}'
        except ImportError:
            return 0, 'pyautogui not installed'

    @desc('Get current process ID', group='system')
    @interruptible()
    def getpid(self):
        """获取当前进程PID"""
        return 1, str(os.getpid())

    @desc('Find processes by name', group='system')
    @interruptible()
    def pgrep(self, name):
        """按进程名查找PID"""
        import psutil
        pids = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if name.lower() in proc.info['name'].lower():
                    pids.append(str(proc.info['pid']))
            except:
                continue
        if pids:
            return 1, '\n'.join(pids)
        return 1, 'No matching processes'

    @desc('Terminate processes by name', group='system')
    @interruptible()
    def pkill(self, name):
        """按进程名终止进程"""
        import psutil
        killed = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if name.lower() in proc.info['name'].lower():
                    proc.terminate()
                    killed.append(str(proc.info['pid']))
            except:
                continue
        if killed:
            return 1, f'Killed processes: {", ".join(killed)}'
        return 1, 'No matching processes'

    @desc('Show network IP addresses', group='network')
    @interruptible()
    def ip(self):
        """显示内网IP、外网IP和归属地"""
        import socket
        import requests
        import netifaces

        # 内网IP
        local_ips = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr['addr']
                    if not ip.startswith('127.'):
                        local_ips.append(ip)

        # 外网IP和归属地
        try:
            resp = requests.get('http://ip-api.com/json/', timeout=5)
            data = resp.json()
            public_ip = data.get('query', 'Unknown')
            city = data.get('city', 'Unknown')
            region = data.get('regionName', 'Unknown')
            country = data.get('country', 'Unknown')
            isp = data.get('isp', 'Unknown')
            location = f"{city}, {region}, {country} ({isp})"
        except:
            public_ip = 'Unable to determine'
            location = 'Unknown'

        result = f"Local IPs:\n  {chr(10).join(local_ips)}\n\nPublic IP: {public_ip}\nLocation: {location}"
        return 1, result

    @desc('List system user accounts', group='system')
    @interruptible()
    def userenum(self):
        """列出系统用户账户"""
        import pwd
        import os

        users = []
        current_user = os.getlogin()

        try:
            for user in pwd.getpwall():
                # macOS: 普通用户 UID 通常是 501 开始
                # 包含当前用户和所有 UID >= 500 的用户
                if user.pw_uid >= 500 or user.pw_name in ['root', 'admin', '_mbsetupuser']:
                    marker = ' [current]' if user.pw_name == current_user else ''
                    users.append(f"{user.pw_name} (UID: {user.pw_uid}){marker}")
        except:
            # Windows fallback
            import subprocess
            result = subprocess.run('net user', shell=True, capture_output=True, text=True)
            return 1, result.stdout

        return 1, '\n'.join(sorted(users, key=lambda x: x.split('UID:')[1].split(')')[0]))

    @desc('Check if current session is root', group='system')
    @interruptible()
    def is_root(self):
        """检查当前是否为 root 权限"""
        import os
        if os.name == 'nt':
            # Windows: 检查是否为管理员
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            return 1, f'Is admin: {is_admin}'
        else:
            # macOS/Linux: 检查 UID
            is_root = os.geteuid() == 0
            return 1, f'Is root: {is_root}'



    @desc('Show system uptime', group='system')
    @interruptible()
    def uptime(self):
        """显示系统运行时间"""
        import psutil
        boot_time = psutil.boot_time()
        from datetime import datetime
        boot_dt = datetime.fromtimestamp(boot_time)
        now = datetime.now()
        uptime_seconds = (now - boot_dt).total_seconds()

        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        return 1, f"Boot time: {boot_dt.strftime('%Y-%m-%d %H:%M:%S')}\nUptime: {days}d {hours}h {minutes}m"