import base64
import json
import os
import tempfile
import uuid

from client.config.config import UPLOAD_BASE_URL
from core.utils.decorator import desc
from core.utils.formatting import format_dict


class CommandJobMixin:
    def _normalize_job_name(self, job_name: str) -> str:
        name = str(job_name or '').strip().replace('\\', '/')
        if name.endswith('.py'):
            name = name[:-3]
        return name.strip('/').strip()

    def _decode_job_payload_arg(self, raw):
        text = str(raw or '').strip()
        prefix = '__json__:'
        if not text.startswith(prefix):
            return text

        encoded = text[len(prefix):]
        decoded = base64.urlsafe_b64decode(encoded.encode()).decode('utf-8')
        return json.loads(decoded)

    def _parse_start_job_request(self, raw):
        payload = self._decode_job_payload_arg(raw)
        if isinstance(payload, dict):
            job_name = self._normalize_job_name(payload.get('job_name') or payload.get('name') or '')
            job_params = payload.get('params') or {}
            if not isinstance(job_params, dict):
                raise ValueError('job params must be an object')
            return {
                'job_name': job_name,
                'job_params': job_params,
                'raw_payload': payload,
            }

        return {
            'job_name': self._normalize_job_name(payload),
            'job_params': {},
            'raw_payload': None,
        }

    def _format_runtime_start_message(self, runtime, title: str) -> str:
        display_name = getattr(runtime, 'display_name', '') or title
        thread_name = getattr(getattr(runtime, 'thread', None), 'name', '') or 'unknown'
        job_key = getattr(runtime, 'job_key', '') or display_name
        return (
            f'{title}: {display_name}\n'
            f'Thread: {thread_name}\n'
            f'Use "stop_job {job_key}" to request stop'
        )

    def _list_remote_job_names(self) -> list[str]:
        import requests

        url = f'{UPLOAD_BASE_URL.rstrip("/")}/api/jobs/list'

        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            raise RuntimeError('Failed to fetch job list')

        data = response.json()
        payload = data.get('data') or []
        jobs = payload.get('jobs', []) if isinstance(payload, dict) else payload

        result = []
        for job in jobs:
            if not isinstance(job, dict):
                continue
            raw_name = job.get('name') or job.get('job_name') or job.get('job_key') or ''
            normalized_name = self._normalize_job_name(raw_name)
            if normalized_name:
                result.append(normalized_name)
        return result

    def _start_remote_job_by_name(self, job_name: str, job_manager, job_params=None):
        normalized = self._normalize_job_name(job_name)
        if not normalized:
            raise ValueError('job name is required')

        self._send_interim_result(1, f'Fetching job: {normalized}')
        script_content = self._fetch_remote_job(normalized)
        return self._start_from_script_content(script_content, normalized, job_manager, job_params=job_params)

    def _attach_remote_runtime_metadata(self, runtime, temp_path: str, job_name: str):
        normalized_job_name = self._normalize_job_name(job_name)
        for target in (runtime, getattr(runtime, 'job_instance', None)):
            if target is None:
                continue
            try:
                target._temp_script_path = temp_path
                target._remote_job_source = 'job_api'
                target._remote_script_name = normalized_job_name
            except Exception:
                pass

    @desc('Start a background job', group='job')
    def start_job(self, job_name: str):
        """
        启动后台任务。
        仅支持从服务端拉取 job 后运行。
        - 必须传任务名
        """
        job_manager = self.socket.runtime.job_manager

        try:
            request_info = self._parse_start_job_request(job_name)
        except Exception as e:
            return 0, f'Invalid start_job payload: {e}'

        normalized = request_info['job_name']
        job_params = request_info['job_params']

        if not normalized:
            return 0, 'Usage: start_job <job_name>'

        self._send_interim_result(1, f'Preparing background job: {normalized}')
        try:
            runtime = self._start_remote_job_by_name(normalized, job_manager, job_params=job_params)
            self._send_final_result(1, self._format_runtime_start_message(runtime, 'Background job started'))
            return None
        except Exception as e:
            return 0, f'Failed to start background job: {normalized}\nError: {e}'

    @desc('Stop a background job', group='job')
    def stop_job(self, job_name: str):
        """
        停止后台任务。
        不传任务名时，列出当前运行中的任务。
        """
        job_name = job_name.strip()
        job_manager = self.socket.runtime.job_manager

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

    @desc('List available background jobs', group='job')
    def jobs(self):
        """
        列出全部可用 job。
        返回纯文本列表：一行一个，无标题，无缩进。
        """
        try:
            items = self._list_remote_job_names()
        except Exception as e:
            return 0, f'Failed to list background jobs: {e}'

        if not items:
            return 1, 'No background jobs available'

        return 1, '\n'.join(items)

    @desc('List running background jobs', group='job')
    def jobs_ps(self):
        """
        列出当前运行中的后台任务。
        """
        job_manager = self.socket.runtime.job_manager
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
        job_manager = self.socket.runtime.job_manager
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
            job_manager = self.socket.runtime.job_manager
            stopped_jobs = job_manager.stop_all_jobs()
            if not stopped_jobs:
                return 1, 'No background jobs are currently running'
            return 1, 'Stop request sent for:\n' + '\n'.join(stopped_jobs)
        except Exception as e:
            return 0, f'Failed to stop background jobs: {e}'

    def _start_from_script_content(self, script_content: str, script_name: str, job_manager, job_params=None):
        """
        从脚本内容启动任务。
        """
        temp_path = ''
        normalized_job_name = self._normalize_job_name(script_name)
        display_script_name = normalized_job_name + '.py' if normalized_job_name else 'remote_job.py'

        try:
            temp_dir = tempfile.gettempdir()
            temp_filename = f'rat_remote_{uuid.uuid4().hex[:8]}.py'
            temp_path = os.path.join(temp_dir, temp_filename)

            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(script_content)

            self._send_interim_result(1, f'Preparing background job from remote job: {display_script_name}')

            runtime = job_manager.start_job(temp_path, normalized_job_name, self.command_id, job_params=job_params)
            self._attach_remote_runtime_metadata(runtime, temp_path, normalized_job_name)
            return runtime
        except Exception:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            raise

    def _fetch_remote_job(self, job_name: str) -> str:
        """
        从服务端 API 获取 job 内容。
        """
        import requests

        normalized_name = self._normalize_job_name(job_name)
        if not normalized_name:
            raise ValueError('job name is required')

        url = f'{UPLOAD_BASE_URL.rstrip("/")}/api/jobs/download'

        try:
            response = requests.get(
                url,
                params={'name': normalized_name},
                timeout=30,
            )
        except Exception as e:
            raise RuntimeError(
                f'Failed to download job from {url}?name={normalized_name}: '
                f'{type(e).__name__}: {e}'
            ) from e

        if response.status_code != 200:
            body = (response.text or '').strip()
            raise RuntimeError(
                f'Failed to download job from {response.url}: '
                f'HTTP {response.status_code} {response.reason}. '
                f'Body: {body[:500] if body else "<empty>"}'
            )

        text = response.text or ''
        if not text.strip():
            raise RuntimeError(
                f'Downloaded empty job from {response.url}'
            )

        return text