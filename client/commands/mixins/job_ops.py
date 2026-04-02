import os
import tempfile
import uuid

from client.config.config import UPLOAD_BASE_URL
from core.utils.decorator import desc
from core.utils.formatting import format_dict


class CommandJobMixin:
    def _normalize_job_name(self, job_name: str) -> str:
        return str(job_name or '').strip()

    def _normalize_script_job_name(self, script_name: str) -> str:
        name = str(script_name or '').strip().replace('\\', '/')
        if name.endswith('.py'):
            name = name[:-3]
        return name.strip('/').strip()

    def _format_runtime_start_message(self, runtime, title: str) -> str:
        display_name = getattr(runtime, 'display_name', '') or title
        thread_name = getattr(getattr(runtime, 'thread', None), 'name', '') or 'unknown'
        job_key = getattr(runtime, 'job_key', '') or display_name
        return (
            f'{title}: {display_name}\n'
            f'Thread: {thread_name}\n'
            f'Use "stop_job {job_key}" to request stop'
        )

    def _list_local_job_names(self) -> list[str]:
        job_manager = self.socket.job_manager
        items = job_manager.list_available_jobs() or []
        result = []
        for item in items:
            text = str(item or '').strip()
            if text:
                result.append(text)
        return result

    def _list_remote_script_names(self) -> list[str]:
        """
        仅返回远程脚本名字列表（纯净，一行一个的语义数据），不给标题/描述。
        """
        import requests

        url = f'{UPLOAD_BASE_URL.rstrip("/")}/api/server/jobs/list'

        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            raise RuntimeError('Failed to fetch remote script list')

        data = response.json()
        payload = data.get('data') or []
        scripts = payload.get('scripts', []) if isinstance(payload, dict) else payload

        result = []
        for script in scripts:
            if not isinstance(script, dict):
                continue
            raw_name = script.get('name') or script.get('job_name') or script.get('job_key') or ''
            normalized_name = self._normalize_script_job_name(raw_name)
            if normalized_name:
                result.append(normalized_name)
        return result

    def _start_remote_job_by_name(self, job_name: str, job_manager):
        normalized = self._normalize_job_name(job_name)
        if not normalized:
            raise ValueError('job name is required')

        self._send_interim_result(1, f'Fetching remote script: {normalized}')
        script_content = self._fetch_remote_script(normalized)
        return self._start_from_script_content(script_content, normalized, job_manager)

    def _attach_remote_runtime_metadata(self, runtime, temp_path: str, script_name: str):
        normalized_job_name = self._normalize_script_job_name(script_name)
        for target in (runtime, getattr(runtime, 'job_instance', None)):
            if target is None:
                continue
            try:
                target._temp_script_path = temp_path
                target._remote_job_source = 'server'
                target._remote_script_name = normalized_job_name
            except Exception:
                pass

    @desc('Start a background job', group='job')
    def start_job(self, job_name: str):
        """
        启动后台任务。
        - 优先尝试本地 client job module
        - 本地找不到时自动回退到 server-side script
        - 必须传任务名
        """
        normalized = self._normalize_job_name(job_name)
        job_manager = self.socket.job_manager

        if not normalized:
            return 0, 'Usage: start_job <job_name>'

        self._send_interim_result(1, f'Preparing background job: {normalized}')
        try:
            runtime = job_manager.start_job(normalized, self.command_id)
            self._send_final_result(1, self._format_runtime_start_message(runtime, 'Background job started'))
            return None
        except Exception as local_error:
            self._send_interim_result(
                1,
                f'Local job not found or failed to start, falling back to remote script: {normalized}',
                0,
            )
            try:
                runtime = self._start_remote_job_by_name(normalized, job_manager)
                self._send_final_result(1, self._format_runtime_start_message(runtime, 'Background job started'))
                return None
            except Exception as remote_error:
                return 0, (
                    f'Failed to start background job: {normalized}\n'
                    f'Local error: {local_error}\n'
                    f'Remote error: {remote_error}'
                )

    @desc('Stop a background job', group='job')
    def stop_job(self, job_name: str):
        """
        停止后台任务。
        不传任务名时，列出当前运行中的任务。
        """
        job_name = job_name.strip()
        job_manager = self.socket.job_manager

        if not job_name:
            running_jobs = job_manager.list_running_jobs()
            if not running_jobs:
                return 1, 'No background jobs are currently running'
            return 1, '\n'.join(running_jobs)

        try:
            runtime = job_manager.stop_job(job_name)
            return 1, f'Stop request sent: {runtime.display_name}'
        except Exception as e:
            return 0, f'Failed to stop background job: {e}'

    @desc('List client local background jobs', group='job')
    def jobs_local(self):
        """
        仅列出 client 本地可用 job。
        返回纯文本列表：一行一个，无标题，无缩进。
        """
        items = self._list_local_job_names()
        return 1, '\n'.join(items)

    @desc('List all available background jobs', group='job')
    def jobs(self):
        """
        列出全部可用 job：server + client。
        返回分组纯文本。
        """
        try:
            local_items = self._list_local_job_names()
        except Exception:
            local_items = []

        try:
            remote_items = self._list_remote_script_names()
        except Exception:
            remote_items = []

        lines = []

        if remote_items:
            lines.append('[server]')
            lines.extend(item for item in remote_items if str(item).strip())

        if local_items:
            if lines:
                lines.append('')
            lines.append('[client]')
            lines.extend(item for item in local_items if str(item).strip())

        if not lines:
            return 1, 'No background jobs available'

        return 1, '\n'.join(lines)

    @desc('List running background jobs', group='job')
    def jobs_ps(self):
        """
        列出当前运行中的后台任务。
        """
        job_manager = self.socket.job_manager
        running_jobs = job_manager.list_running_jobs()
        if not running_jobs:
            return 1, 'No background jobs are currently running'
        return 1, '\n'.join(running_jobs)

    @desc('Show background job status', group='job')
    def job_status(self, job_name: str):
        """
        查看指定后台任务状态。
        """
        job_name = job_name.strip()
        job_manager = self.socket.job_manager
        if not job_name:
            return 0, 'Usage: job_status <job_name>'

        try:
            status_info = job_manager.get_job_status(job_name)
            return 1, format_dict(status_info)
        except Exception as e:
            return 0, f'Failed to query background job status: {e}'

    @desc('Stop all background jobs', group='job')
    def stop_all_jobs(self):
        """
        停止所有后台任务。
        """
        try:
            job_manager = self.socket.job_manager
            stopped_jobs = job_manager.stop_all_jobs()
            if not stopped_jobs:
                return 1, 'No background jobs are currently running'
            return 1, 'Stop request sent for:\n' + '\n'.join(stopped_jobs)
        except Exception as e:
            return 0, f'Failed to stop background jobs: {e}'

    def _start_from_script_content(self, script_content: str, script_name: str, job_manager):
        """
        从脚本内容启动任务。
        """
        temp_path = ''
        normalized_job_name = self._normalize_script_job_name(script_name)
        display_script_name = normalized_job_name + '.py' if normalized_job_name else 'remote_job.py'

        try:
            temp_dir = tempfile.gettempdir()
            temp_filename = f'rat_remote_{uuid.uuid4().hex[:8]}.py'
            temp_path = os.path.join(temp_dir, temp_filename)

            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(script_content)

            self._send_interim_result(1, f'Preparing background job from remote script: {display_script_name}')

            runtime = job_manager.start_job_rem(temp_path, normalized_job_name, self.command_id)
            self._attach_remote_runtime_metadata(runtime, temp_path, normalized_job_name)
            return runtime
        except Exception:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            raise

    def _fetch_remote_script(self, script_name: str) -> str:
        """
        从服务端 API 获取脚本内容。
        """
        import requests

        normalized_name = self._normalize_job_name(script_name)
        if not normalized_name:
            raise ValueError('script name is required')

        url = f'{UPLOAD_BASE_URL.rstrip("/")}/api/server/jobs/download'
        response = requests.get(
            url,
            params={'name': normalized_name},
            timeout=30,
        )

        if response.status_code != 200:
            raise RuntimeError(f'Failed to download script: {response.text}')

        return response.text