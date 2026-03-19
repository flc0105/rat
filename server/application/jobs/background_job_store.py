import copy
import threading
from datetime import datetime

from server.models.artifact import ArtifactRecord
from server.models.jobs import BackgroundJobFileRef, BackgroundJobMessage, BackgroundJobState


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

        return BackgroundJobState(
            job_id=job_id,
            client_id=payload.get('client_id', ''),
            job_name=job_name,
            job_key=job_key,
            display_name=display_name,
            thread_name=payload.get('thread_name', ''),
            command_id=payload.get('command_id'),
            state='unknown',
            created_at=created_at,
            started_at='',
            stopped_at='',
            updated_at=created_at,
            last_message='',
            message_count=0,
            file_count=0,
            messages=[],
            files=[],
        ).to_dict()

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
        model = BackgroundJobState.from_dict(job)

        model.job_name = payload.get('job_name') or model.job_name or ''
        model.job_key = payload.get('job_key') or model.job_key or ''
        model.thread_name = payload.get('thread_name') or model.thread_name or ''
        model.command_id = payload.get('command_id', model.command_id)
        model.client_id = payload.get('client_id') or model.client_id or ''
        model.updated_at = payload.get('time') or self._now_iso()

        display_name = payload.get('display_name')
        if display_name:
            model.display_name = display_name
        elif not model.display_name:
            display_base = model.job_key or model.job_name or 'job'
            model.display_name = f'{display_base}#{model.job_id[:8]}'

        job.clear()
        job.update(model.to_dict())

    def _resolve_job_file_view(self, file_item: dict) -> dict:
        copied = dict(file_item)
        artifact_id = (copied.get('artifact_id') or '').strip()

        if artifact_id and self.artifact_service is not None:
            try:
                artifact_payload = self.artifact_service.get_artifact_by_id(artifact_id)
                artifact = ArtifactRecord.from_dict(artifact_payload)
                return BackgroundJobFileRef(
                    artifact_id=artifact.artifact_id,
                    artifact_type=artifact.artifact_type,
                    category=artifact.category,
                    hostname=artifact.hostname,
                    client_id=artifact.client_id,
                    original_name=artifact.original_name,
                    stored_name=artifact.stored_name,
                    size=artifact.size,
                    created_at=artifact.created_at,
                    source_type=artifact.source_type,
                    download_url=artifact.download_url,
                    raw_url=artifact.raw_url,
                    preview_url=artifact.preview_url,
                    is_available=bool(artifact_payload.get('is_available', True)),
                    status_text=artifact_payload.get('status_text', ''),
                ).to_dict()
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
            model = BackgroundJobState.from_dict(job)

            state = (payload.get('state') or '').strip() or model.state or 'unknown'
            event_time = payload.get('time') or self._now_iso()

            model.state = state
            model.updated_at = event_time

            if state == 'running' and not model.started_at:
                model.started_at = event_time

            if state in ('stopped', 'error') and not model.stopped_at:
                model.stopped_at = event_time

            status_text = str(payload.get('text') or '').strip()
            if status_text:
                model.last_message = status_text

            updated = model.to_dict()
            self._get_client_bucket(model.client_id)[model.job_id] = updated
            return copy.deepcopy(updated)

    def append_message_report(self, payload: dict) -> dict:
        with self._lock:
            job = self._get_or_create_job(payload)
            model = BackgroundJobState.from_dict(job)

            message = BackgroundJobMessage(
                status=payload.get('status', 1),
                text=str(payload.get('text') or ''),
                eof=payload.get('eof', 0),
                time=payload.get('time') or self._now_iso(),
            )

            messages = list(model.messages or [])
            messages.append(message.to_dict())

            model.messages = messages
            model.message_count += 1
            model.last_message = message.text
            model.updated_at = message.time

            updated = model.to_dict()
            self._get_client_bucket(model.client_id)[model.job_id] = updated
            return copy.deepcopy(updated)

    def append_file_report(self, payload: dict) -> dict:
        with self._lock:
            job = self._get_or_create_job(payload)
            model = BackgroundJobState.from_dict(job)

            artifact = ArtifactRecord.from_dict(payload.get('file') or {})
            file_ref = BackgroundJobFileRef(
                artifact_id=artifact.artifact_id,
                artifact_type=artifact.artifact_type,
                category=artifact.category,
                hostname=artifact.hostname,
                client_id=artifact.client_id,
                original_name=artifact.original_name,
                stored_name=artifact.stored_name,
                size=artifact.size,
                created_at=artifact.created_at or payload.get('time') or self._now_iso(),
                source_type=artifact.source_type,
                download_url=artifact.download_url,
                raw_url=artifact.raw_url,
                preview_url=artifact.preview_url,
                is_available=True,
                status_text='',
            )

            files = list(model.files or [])
            files.append(file_ref.to_dict())

            model.files = files
            model.file_count += 1
            model.updated_at = file_ref.created_at

            updated = model.to_dict()
            self._get_client_bucket(model.client_id)[model.job_id] = updated
            return copy.deepcopy(updated)

    def get_jobs_for_client(self, client_id: str) -> list[dict]:
        with self._lock:
            bucket = self._jobs_by_client.get(client_id, {})
            items = [copy.deepcopy(item) for item in bucket.values()]

        for item in items:
            model = BackgroundJobState.from_dict(item)
            files = [self._resolve_job_file_view(file_item) for file_item in model.files or []]
            model.files = files
            model.file_count = len(files)
            item.update(model.to_dict())

        items.sort(key=lambda item: item.get('updated_at', ''), reverse=True)
        return items