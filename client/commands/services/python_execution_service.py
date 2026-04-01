import base64
import os
import pickle
import subprocess
import sys
import tempfile
import traceback


class PythonExecutionService:
    """
    Python 执行基础设施。

    职责：
    - 将 Python 代码统一切到可取消的子进程执行模型
    - 统一 script / pyexec / pyexec_gen / pyexec_subprocess_gen 的底层执行路径
    - 负责临时脚本文件的生成与清理
    """

    def __init__(self, owner, process_service):
        self.owner = owner
        self.process_service = process_service

    def _normalize_kwargs(self, kwargs):
        if isinstance(kwargs, dict):
            return dict(kwargs)
        return {}

    def _serialize_kwargs(self, kwargs) -> str:
        payload = pickle.dumps(self._normalize_kwargs(kwargs))
        return base64.b64encode(payload).decode('ascii')

    def _build_bootstrap_script(self, code, kwargs=None) -> str:
        kwargs_payload = self._serialize_kwargs(kwargs)

        return f"""import base64
import pickle
import traceback

USER_CODE = {code!r}
KWARGS_PAYLOAD = {kwargs_payload!r}

try:
    kwargs = pickle.loads(base64.b64decode(KWARGS_PAYLOAD.encode('ascii')))
except Exception:
    kwargs = {{}}

exec_globals = {{}}
exec_globals.update(kwargs)
exec_globals['kwargs'] = kwargs

try:
    exec(compile(USER_CODE, '<remote_pyexec>', 'exec'), exec_globals)
except SystemExit:
    raise
except Exception:
    traceback.print_exc()
    raise
"""

    def _create_temp_script(self, code, kwargs=None):
        temp_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.py',
            delete=False,
            encoding='utf-8'
        )

        try:
            temp_file.write(self._build_bootstrap_script(code, kwargs=kwargs))
            temp_file.flush()
            return temp_file.name
        finally:
            temp_file.close()

    def _cleanup_temp_script(self, temp_path: str):
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except Exception:
                pass

    def _build_python_command(self, temp_path: str):
        return [sys.executable, '-u', temp_path]

    def execute_collect(self, code, kwargs=None, timeout=None):
        """
        执行 Python 代码并在结束后返回汇总输出。
        """
        temp_path = self._create_temp_script(code, kwargs=kwargs)
        process = None

        try:
            process = self.process_service.start_stream_process(
                self._build_python_command(temp_path),
                shell=False,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1
            )

            return_code = self.process_service.wait_process_with_cancel_support(process, timeout=timeout)
            stdout, stderr = process.communicate()
            output = f'{stdout or ""}{stderr or ""}'

            if return_code == 0:
                return 1, output
            if output.strip():
                return 0, output
            return 0, f'Process exited with code {return_code}'
        finally:
            self._cleanup_temp_script(temp_path)

    def execute_stream(self, code, kwargs=None, timeout=None):
        """
        执行 Python 代码并流式输出结果。
        """
        temp_path = self._create_temp_script(code, kwargs=kwargs)
        process = None

        try:
            process = self.process_service.start_stream_process(
                self._build_python_command(temp_path),
                shell=False,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1
            )

            stdout_thread, stderr_thread = self.process_service.start_output_threads(process)
            self.process_service.wait_stream_process(process, timeout=timeout)

            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)

            if process.returncode == 0:
                self.owner._send_final_result(1, 'Code execution completed')
            else:
                self.owner._send_final_result(0, f'Process exited with code {process.returncode}')
        finally:
            self._cleanup_temp_script(temp_path)





