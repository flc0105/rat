import contextlib
import io
import locale
import os
import signal
import subprocess
import sys
import threading
import time

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.interrupts import interruptible, cancel_policy, timeout
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

    # ------------------ 通用输出/子进程工具 ------------------ #
    def _get_default_encoding(self):
        """
        获取系统默认编码
        """
        return locale.getdefaultlocale()[1] or 'utf-8'

    def _stream_process_output(self, stream):
        """
        持续读取子进程输出流并发送中间结果
        """
        encoding = self._get_default_encoding()
        while True:
            self._ensure_not_interrupted(fallback_timeout=self.DEFAULT_STREAM_TIMEOUT)
            line = stream.readline()
            if not line:
                break
            self._send_interim_result(1, line.decode(encoding, errors='replace').rstrip('\n'))

    def _build_process_creation_kwargs(self) -> dict:
        """
        构造可被强制终止的一组子进程创建参数
        """
        kwargs = {}

        if os.name == 'nt':
            kwargs['creationflags'] = getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
        else:
            kwargs['start_new_session'] = True

        return kwargs

    def _terminate_process(self, process: subprocess.Popen):
        """
        终止子进程；优先杀整个进程组
        """
        if process is None:
            return

        try:
            if process.poll() is not None:
                return
        except Exception:
            return

        try:
            if os.name == 'nt':
                process.kill()
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

        try:
            process.wait(timeout=self.PROCESS_KILL_GRACE_SECONDS)
        except Exception:
            pass

    def _wait_process_with_cancel_support(self, process: subprocess.Popen, timeout=None):
        effective_timeout = self.DEFAULT_STREAM_TIMEOUT if timeout is None else timeout

        while True:
            try:
                self._ensure_not_interrupted(fallback_timeout=effective_timeout)
                return_code = process.poll()
                if return_code is not None:
                    return return_code
                time.sleep(self.PROCESS_WAIT_POLL_INTERVAL)
            except CommandCancelledError:
                self._terminate_process(process)
                raise
            except CommandTimeoutError:
                self._terminate_process(process)
                raise subprocess.TimeoutExpired(process.args, effective_timeout)

    def _run_shell_command(self, command, timeout=None):
        """
        执行一次性 shell 命令
        """
        encoding = self._get_default_encoding()
        effective_timeout = self.DEFAULT_SHELL_TIMEOUT if timeout is None else timeout

        process = subprocess.Popen(
            command,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding=encoding,
            errors='replace',
            **self._build_process_creation_kwargs()
        )
        self._register_cancel_handler(lambda: self._terminate_process(process))

        try:
            while True:
                self._ensure_not_interrupted(fallback_timeout=effective_timeout)
                try:
                    stdout, stderr = process.communicate(timeout=self.PROCESS_WAIT_POLL_INTERVAL)
                    return subprocess.CompletedProcess(
                        args=command,
                        returncode=process.returncode,
                        stdout=stdout,
                        stderr=stderr
                    )
                except subprocess.TimeoutExpired:
                    continue
        except CommandCancelledError:
            self._terminate_process(process)
            raise
        except CommandTimeoutError:
            self._terminate_process(process)
            raise subprocess.TimeoutExpired(process.args, effective_timeout)
        except Exception:
            self._terminate_process(process)
            raise

    def _start_stream_process(self, command):
        """
        启动带流式输出的子进程
        """
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            **self._build_process_creation_kwargs()
        )
        self._register_cancel_handler(lambda: self._terminate_process(process))
        return process

    def _start_output_threads(self, process):
        """
        为 stdout/stderr 启动输出读取线程
        """
        stdout_thread = threading.Thread(target=self._stream_process_output, args=(process.stdout,))
        stderr_thread = threading.Thread(target=self._stream_process_output, args=(process.stderr,))
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()
        return stdout_thread, stderr_thread

    def _wait_stream_process(self, process, timeout=None):
        """
        等待流式子进程结束；超时则强制终止
        """
        effective_timeout = self.DEFAULT_STREAM_TIMEOUT if timeout is None else timeout
        return self._wait_process_with_cancel_support(process, timeout=effective_timeout)

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
        if os.name == 'nt':
            creation_flags = 0
            for attr_name in ('DETACHED_PROCESS', 'CREATE_NEW_PROCESS_GROUP'):
                creation_flags |= getattr(subprocess, attr_name, 0)

            process = subprocess.Popen(
                command,
                shell=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags
            )
            return process

        process = subprocess.Popen(
            command,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        return process

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

    # @desc('Execute Python code', group='shell')
    # @interruptible()
    # @cancel_policy(False)
    # def pyexec(self, code, kwargs=None):
    #     if kwargs is None:
    #         kwargs = {}
    #     output = io.StringIO()
    #     with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
    #         exec(code, kwargs)
    #     return 1, output.getvalue()

    @desc('Execute Python code', group='shell')
    @interruptible()
    @cancel_policy(False)
    def pyexec(self, code, kwargs=None):
        try:
            if kwargs is None:
                kwargs = {}

            # 创建执行环境，将 kwargs 合并到全局变量中
            exec_globals = {}
            exec_globals.update(kwargs)  # 用户传入的参数

            # 同时注入 kwargs 本身，方便脚本使用
            exec_globals['kwargs'] = kwargs

            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                exec(code, exec_globals)

            return 1, output.getvalue()
        except Exception as e:
            import traceback
            error_msg = traceback.format_exc()
            output.write(f"\n[ERROR] Script execution failed:\n{error_msg}")
            return 0, output.getvalue()

    @desc('Execute Python code with streaming output (generator)', group='shell')
    @interruptible()
    @cancel_policy(False)
    def pyexec_gen(self, code, kwargs=None):
        """
        执行 Python 代码并生成输出流
        """
        if kwargs is None:
            kwargs = {}

        try:
            import sys
            from io import StringIO

            # 创建自定义的 StringIO 来捕获输出
            class StreamGenerator:
                def __init__(self, owner):
                    self.owner = owner
                    self.buffer = ''

                def write(self, text):
                    if text:
                        self.buffer += text
                        lines = self.buffer.split('\n')
                        self.buffer = lines[-1]
                        for line in lines[:-1]:
                            if line:
                                self.owner._send_interim_result(1, line, 0)

                def flush(self):
                    if self.buffer:
                        self.owner._send_interim_result(1, self.buffer, 0)
                        self.buffer = ''

            # 保存原始 stdout/stderr
            old_stdout = sys.stdout
            old_stderr = sys.stderr

            # 创建捕获器
            generator = StreamGenerator(self)

            sys.stdout = generator
            sys.stderr = generator

            try:
                exec(code, kwargs)
                generator.flush()
            except Exception as e:
                self._send_interim_result(0, f'Error: {e}', 0)
                return 0, f'Execution failed: {e}'
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            self._send_final_result(1, "Code execution completed")

        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out'
        except Exception as e:
            return 0, f'Failed to execute code: {e}'

    @desc('Execute Python code in subprocess with streaming output', group='shell')
    @interruptible()
    def pyexec_subprocess_gen(self, code, kwargs=None):
        """
        在子进程中执行 Python 代码，实时流式输出，支持强制取消
        """
        if kwargs is None:
            kwargs = {}

        import subprocess
        import tempfile
        os
        import threading

        temp_file = None
        process = None

        try:
            # 创建临时文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
                # 写入用户代码
                f.write(code)
                temp_file = f.name

            # 启动子进程
            process = subprocess.Popen(
                ['python3', temp_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # 行缓冲
            )

            # 注册取消处理器
            def cancel_handler():
                if process and process.poll() is None:
                    try:
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                    except Exception:
                        pass

            self._register_cancel_handler(cancel_handler)

            # 实时读取输出并发送
            def read_stream(stream, is_stderr=False):
                for line in iter(stream.readline, ''):
                    self._ensure_not_interrupted()
                    if line:
                        status = 0 if is_stderr else 1
                        self._send_interim_result(status, line.rstrip('\n'), 0)

            # 创建读取线程
            stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, False))
            stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, True))
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            # 等待进程结束
            while True:
                self._ensure_not_interrupted()
                if process.poll() is not None:
                    break
                time.sleep(0.1)

            # 等待读取线程结束
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)

            if process.returncode == 0:
                self._send_final_result(1, "Code execution completed")
            else:
                self._send_final_result(0, f"Process exited with code {process.returncode}")

        except CommandCancelledError:
            if process and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except Exception:
                    pass
            self._send_final_result(0, 'Command cancelled')
        except CommandTimeoutError:
            if process and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except Exception:
                    pass
            self._send_final_result(0, 'Command timed out')
        except Exception as e:
            self._send_final_result(0, f'Failed to execute code: {e}')
        finally:
            # 清理临时文件
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except Exception:
                    pass

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

