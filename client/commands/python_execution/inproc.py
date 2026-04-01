import contextlib
import io
import traceback

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.python_execution.base import PythonExecutionStrategy


class InProcessPythonExecutionStrategy(PythonExecutionStrategy):
    MODE_NAME = 'inproc'

    def is_cancel_supported(self) -> bool:
        return False

    def _build_exec_globals(self, kwargs=None):
        if kwargs is None:
            kwargs = {}

        exec_globals = {}
        exec_globals.update(kwargs)  # 用户传入的参数

        # 同时注入 kwargs 本身，方便脚本使用
        exec_globals['kwargs'] = kwargs
        return exec_globals

    def execute_collect(self, code, kwargs=None, timeout=None):
        self.configure_context()

        output = io.StringIO()
        try:
            exec_globals = self._build_exec_globals(kwargs)
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                exec(code, exec_globals)
            return 1, output.getvalue()
        except Exception:
            error_msg = traceback.format_exc()
            output.write(f"\n[ERROR] Script execution failed:\n{error_msg}")
            return 0, output.getvalue()

    def execute_stream(self, code, kwargs=None, timeout=None):
        """
        执行 Python 代码并生成输出流
        """
        self.configure_context()

        if kwargs is None:
            kwargs = {}

        try:
            import sys

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
            generator = StreamGenerator(self.owner)

            sys.stdout = generator
            sys.stderr = generator

            try:
                exec_globals = self._build_exec_globals(kwargs)
                exec(code, exec_globals)
                generator.flush()
            except Exception as e:
                self.owner._send_interim_result(0, f'Error: {e}', 0)
                return 0, f'Execution failed: {e}'
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            self.owner._send_final_result(1, "Code execution completed")

        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out'
        except Exception as e:
            return 0, f'Failed to execute code: {e}'


