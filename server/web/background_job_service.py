import os
from datetime import datetime

from server.connection.client_connection import ClientConnection


class BackgroundJobService:
    """
    后台任务 Web 服务。

    职责：
    - 列出可启动任务
    - 启动 / 停止后台任务
    - 接收客户端通过 HTTP 上报的任务消息/状态/文件
    - 对外提供任务监控数据
    """

    def __init__(self, server, event_bus, job_store):
        self.server = server
        self.event_bus = event_bus
        self.job_store = job_store

    def _collect_result(self, result_iter):
        final_status = 1
        parts = []

        for status, text in result_iter:
            final_status = status
            if text is not None:
                parts.append(str(text))

        return final_status, '\n'.join(part for part in parts if part).strip()

    def _run_text_command(self, client_id: str, command: str) -> str:
        conn = self.server.get_target_connection_by_client_id(client_id)
        status, text = self._collect_result(conn.send_command(command))

        if status != 1:
            raise RuntimeError(text or 'Remote command failed')

        return text

    def _serialize_available_job(self, job_name: str) -> dict:
        normalized = str(job_name or '').strip()
        return {
            'job_name': normalized,
            'job_key': os.path.splitext(os.path.basename(normalized))[0] if normalized else '',
        }

    def _parse_available_jobs_text(self, text: str) -> list[dict]:
        lines = [line.strip() for line in str(text or '').splitlines() if line.strip()]
        if not lines:
            return []

        if len(lines) == 1 and lines[0] == 'No job modules available':
            return []

        return [self._serialize_available_job(line) for line in lines]

    def list_available_jobs(self, client_id: str) -> list[dict]:
        text = self._run_text_command(client_id, 'start_job')
        return self._parse_available_jobs_text(text)

    def start_job(self, client_id: str, job_name: str) -> dict:
        job_name = (job_name or '').strip()
        if not job_name:
            raise ValueError('job_name is required')

        text = self._run_text_command(client_id, f'start_job {job_name}')
        return {
            'client_id': client_id,
            'job_name': job_name,
            'message': text,
        }

    def stop_job(self, client_id: str, job_key: str) -> dict:
        job_key = (job_key or '').strip()
        if not job_key:
            raise ValueError('job_key is required')

        text = self._run_text_command(client_id, f'stop_job {job_key}')
        return {
            'client_id': client_id,
            'job_key': job_key,
            'message': text,
        }

    def _calc_duration_seconds(self, started_at: str, stopped_at: str, state: str) -> int:
        if not started_at:
            return 0

        try:
            start_dt = datetime.fromisoformat(started_at)
            end_text = stopped_at
            if not end_text and state not in ('stopped', 'error'):
                end_text = datetime.now().isoformat()
            end_dt = datetime.fromisoformat(end_text) if end_text else datetime.now()
            return max(int((end_dt - start_dt).total_seconds()), 0)
        except Exception:
            return 0

    def _serialize_job(self, job: dict) -> dict:
        state = job.get('state', '')
        started_at = job.get('started_at', '')
        stopped_at = job.get('stopped_at', '')

        return {
            'job_id': job.get('job_id', ''),
            'client_id': job.get('client_id', ''),
            'job_name': job.get('job_name', ''),
            'job_key': job.get('job_key', ''),
            'display_name': job.get('display_name', ''),
            'thread_name': job.get('thread_name', ''),
            'command_id': job.get('command_id'),
            'state': state,
            'created_at': job.get('created_at', ''),
            'started_at': started_at,
            'stopped_at': stopped_at,
            'updated_at': job.get('updated_at', ''),
            'duration_seconds': self._calc_duration_seconds(started_at, stopped_at, state),
            'last_message': job.get('last_message', ''),
            'message_count': job.get('message_count', 0),
            'file_count': job.get('file_count', 0),
            'messages': job.get('messages', []),
            'files': job.get('files', []),
        }

    def list_jobs(self, client_id: str) -> list[dict]:
        jobs = self.job_store.get_jobs_for_client(client_id)
        return [self._serialize_job(job) for job in jobs]

    def ingest_report(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError('Invalid background job payload')

        event_type = (payload.get('event_type') or '').strip()
        if not event_type:
            raise ValueError('event_type is required')

        if event_type == 'status':
            job = self.job_store.apply_status_report(payload)
            serialized = self._serialize_job(job)
            self.event_bus.publish('background_job_status', serialized)
            return serialized

        if event_type == 'message':
            job = self.job_store.append_message_report(payload)
            serialized = self._serialize_job(job)
            self.event_bus.publish('background_job_message', serialized)
            return serialized

        if event_type == 'file':
            job = self.job_store.append_file_report(payload)
            serialized = self._serialize_job(job)
            self.event_bus.publish('background_job_file', serialized)
            return serialized

        raise ValueError(f'Unsupported event_type: {event_type}')