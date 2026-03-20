import contextlib
import io
import locale
import os
import subprocess
import sys
import threading
import time

from core.utils.decorator import desc


class CommandExecutionMixin:
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
            line = stream.readline()
            if not line:
                break
            self._send_interim_result(1, line.decode(encoding, errors='replace').rstrip('\n'))

    def _run_shell_command(self, command):
        """
        执行一次性 shell 命令
        """
        encoding = self._get_default_encoding()
        return subprocess.run(
            command,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding=encoding,
            errors='replace',
            timeout=30
        )

    def _start_stream_process(self, command):
        """
        启动带流式输出的子进程
        """
        return subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL
        )

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

    def _build_restart_command(self):
        """
        构造当前程序重启命令
        """
        if os.name == 'nt':
            from core.utils.client_util.win32util import get_executable_path
            return get_executable_path()

        if os.name == 'posix':
            executable_path = os.path.realpath(sys.executable)
            script_path = os.path.realpath(''.join(sys.argv))
            return f'{executable_path} {script_path} '

        raise RuntimeError(f'Unsupported platform: {os.name}')

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
    def cd(self, path):
        try:
            os.chdir(path)
            return 1, ""
        except Exception as e:
            return 0, f'Failed to change directory: {e}'

    @desc('Run a shell command', group='shell')
    def shell(self, command):
        try:
            result = self._run_shell_command(command)
            if result.returncode == 0:
                return 1, result.stdout
            return 0, result.stderr or f'Command exited with code {result.returncode}'
        except subprocess.TimeoutExpired:
            return 0, 'Command timed out'
        except Exception as e:
            return 0, f'Failed to execute command: {e}'

    @desc('Run a program in background', group='shell')
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
        except Exception as e:
            return 0, f'Failed to start background process: {e}'

    @desc('Run a command with live output', group='shell')
    def read(self, command):
        try:
            process = self._start_stream_process(command)
            self._start_output_threads(process)
            process.wait()
            time.sleep(0.1)

            if process.returncode == 0:
                self._send_final_result(1, "Command completed")
            else:
                self._send_final_result(0, f'Command exited with code {process.returncode}')
        except Exception as e:
            self._send_final_result(0, f'Failed to execute command: {e}')

    @desc('Execute Python code', group='shell')
    def pyexec(self, code, kwargs=None):
        if kwargs is None:
            kwargs = {}
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            exec(code, kwargs)
        return 1, output.getvalue()

    # ------------------ 连接控制 ------------------ #
    @desc('Terminate current session', group='session')
    def kill(self):
        self.socket.close()
        sys.exit(0)

    @desc('Restart client process and reconnect', group='session')
    def reset(self):
        restart_command = self._build_restart_command()
        if os.name == 'nt':
            subprocess.Popen(restart_command)
        elif os.name == 'posix':
            subprocess.Popen(restart_command, shell=True)
        self.socket.close()
        sys.exit(0)