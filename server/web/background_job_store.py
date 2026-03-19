import copy
import threading
from datetime import datetime


class BackgroundJobStore:
    """
    后台任务状态存储。

    职责：
    - 按 client_id + job_id 保存后台任务运行态
    - 保存消息、文件、状态变更
    - 提供查询能力
    """

    def __init__(self):
        self._jobs_by_client = {}
        self._lock = threading.RLock()
        self.artifact_service = None

    def _now_iso(self) -> str:
        return datetime.now().isoformat()

    def _get_client_bucket(self, client_id: str) -> dict:
        return self._jobs_by_client.setdefault(client_id, {})

    def _build_default_job(self, payload: dict) -> dict:
        job_id = payload.get('job_id', '')
        job_name = payload.get('job_name', '')
        job_key = payload.get('job_key', '')
        created_at = payload.get('time') or self._now_iso()

        display_base = job_key or job_name or 'job'
        display_name = payload.get('display_name') or f'{display_base}#{job_id[:8]}' if job_id else display_base

        return {
            'job_id': job_id,
            'client_id': payload.get('client_id', ''),
            'job_name': job_name,
            'job_key': job_key,
            'display_name': display_name,
            'thread_name': payload.get('thread_name', ''),
            'command_id': payload.get('command_id'),
            'state': 'unknown',
            'created_at': created_at,
            'started_at': '',
            'stopped_at': '',
            'updated_at': created_at,
            'last_message': '',
            'message_count': 0,
            'file_count': 0,
            'messages': [],
            'files': [],
        }

    def _get_or_create_job(self, payload: dict) -> dict:
        client_id = payload.get('client_id', '')
        job_id = payload.get('job_id', '')

        if not client_id:
            raise ValueError('client_id is required')
        if not job_id:
            raise ValueError('job_id is required')

        bucket = self._get_client_bucket(client_id)
        job = bucket.get(job_id)

        if job is None:
            job = self._build_default_job(payload)
            bucket[job_id] = job

        self._sync_job_metadata(job, payload)
        return job

    def _sync_job_metadata(self, job: dict, payload: dict):
        job['job_name'] = payload.get('job_name') or job.get('job_name') or ''
        job['job_key'] = payload.get('job_key') or job.get('job_key') or ''
        job['thread_name'] = payload.get('thread_name') or job.get('thread_name') or ''
        job['command_id'] = payload.get('command_id', job.get('command_id'))
        job['client_id'] = payload.get('client_id') or job.get('client_id') or ''
        job['updated_at'] = payload.get('time') or self._now_iso()

        display_name = payload.get('display_name')
        if display_name:
            job['display_name'] = display_name
        elif not job.get('display_name'):
            display_base = job.get('job_key') or job.get('job_name') or 'job'
            job['display_name'] = f'{display_base}#{job.get("job_id", "")[:8]}'


    def _resolve_job_file_view(self, file_item: dict) -> dict:
        copied = dict(file_item)
        artifact_id = (copied.get('artifact_id') or '').strip()

        if artifact_id and self.artifact_service is not None:
            try:
                artifact = self.artifact_service.get_artifact_by_id(artifact_id)
                copied.update({
                    'artifact_type': artifact.get('artifact_type', copied.get('artifact_type', '')),
                    'category': artifact.get('category', copied.get('category', '')),
                    'hostname': artifact.get('hostname', copied.get('hostname', '')),
                    'client_id': artifact.get('client_id', copied.get('client_id', '')),
                    'original_name': artifact.get('original_name', copied.get('original_name', '')),
                    'stored_name': artifact.get('stored_name', copied.get('stored_name', '')),
                    'relative_path': artifact.get('saved_path', copied.get('relative_path', '')),
                    'size': artifact.get('size', copied.get('size', 0)),
                    'download_url': artifact.get('download_url', copied.get('download_url', '')),
                    'raw_url': artifact.get('raw_url', copied.get('raw_url', '')),
                    'preview_url': artifact.get('preview_url', copied.get('preview_url', '')),
                    'source_type': artifact.get('source_type', copied.get('source_type', '')),
                    'is_available': artifact.get('is_available', True),
                    'status_text': artifact.get('status_text', ''),
                })
                return copied
            except Exception:
                copied['is_available'] = False
                copied['status_text'] = copied.get('status_text') or 'Artifact removed'
                return copied

        copied['is_available'] = bool(copied.get('download_url'))
        copied['status_text'] = '' if copied['is_available'] else 'File removed'
        return copied

    def apply_status_report(self, payload: dict) -> dict:
        with self._lock:
            job = self._get_or_create_job(payload)
            state = (payload.get('state') or '').strip() or job.get('state') or 'unknown'
            event_time = payload.get('time') or self._now_iso()

            job['state'] = state
            job['updated_at'] = event_time

            if state == 'running' and not job.get('started_at'):
                job['started_at'] = event_time

            if state in ('stopped', 'error') and not job.get('stopped_at'):
                job['stopped_at'] = event_time

            status_text = str(payload.get('text') or '').strip()
            if status_text:
                job['last_message'] = status_text

            return copy.deepcopy(job)

    def append_message_report(self, payload: dict) -> dict:
        with self._lock:
            job = self._get_or_create_job(payload)

            message = {
                'status': payload.get('status', 1),
                'text': str(payload.get('text') or ''),
                'eof': payload.get('eof', 0),
                'time': payload.get('time') or self._now_iso(),
            }

            job['messages'].append(message)
            job['message_count'] += 1
            job['last_message'] = message['text']
            job['updated_at'] = message['time']

            return copy.deepcopy(job)

    def append_file_report(self, payload: dict) -> dict:
        with self._lock:
            job = self._get_or_create_job(payload)

            file_info = payload.get('file') or {}
            if not isinstance(file_info, dict):
                file_info = {}

            saved_file = {
                'artifact_id': file_info.get('artifact_id', ''),
                'artifact_type': file_info.get('artifact_type', ''),
                'category': file_info.get('category', ''),
                'hostname': file_info.get('hostname', ''),
                'client_id': file_info.get('client_id', ''),
                'original_name': file_info.get('original_name', ''),
                'stored_name': file_info.get('stored_name', ''),
                'relative_path': file_info.get('relative_path', ''),
                'size': file_info.get('size', 0),
                'source_type': file_info.get('source_type', ''),
                'download_url': file_info.get('download_url', ''),
                'raw_url': file_info.get('raw_url', ''),
                'preview_url': file_info.get('preview_url', ''),
                'time': payload.get('time') or self._now_iso(),
            }

            job['files'].append(saved_file)
            job['file_count'] += 1
            job['updated_at'] = saved_file['time']

            return copy.deepcopy(job)

    def get_jobs_for_client(self, client_id: str) -> list[dict]:
        with self._lock:
            bucket = self._jobs_by_client.get(client_id, {})
            items = [copy.deepcopy(item) for item in bucket.values()]

        for item in items:
            files = [self._resolve_job_file_view(file_item) for file_item in item.get('files') or []]
            item['files'] = files
            item['file_count'] = len(files)

        items.sort(key=lambda item: item.get('updated_at', ''), reverse=True)
        return items
