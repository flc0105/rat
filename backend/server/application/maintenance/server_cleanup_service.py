import os
import shutil
import threading
import time
import tempfile
import uuid
from datetime import datetime, timezone

from core.utils.logger import logger


class ServerCleanupService:
    """Server-side cleanup runner for transient and cache data."""

    LOG_PREFIX = 'server_cleanup_'

    def __init__(
        self,
        *,
        event_bus,
        notification_history_api,
        artifact_service,
        agent_output_registry,
        cleanup_items,
        start_delay_seconds: int,
        log_root_dir: str,
    ):
        self.event_bus = event_bus
        self.notification_history_api = notification_history_api
        self.artifact_service = artifact_service
        self.agent_output_registry = agent_output_registry
        self.cleanup_items = tuple(cleanup_items or ())
        self.start_delay_seconds = max(0, int(start_delay_seconds or 0))
        self.log_root_dir = os.path.abspath(log_root_dir)
        self.startup_epoch = time.time()
        self._lock = threading.RLock()
        self._startup_timer = None
        self._startup_scheduled = False

        os.makedirs(self.log_root_dir, exist_ok=True)

        self._server_handlers = {
            'notifications': self._cleanup_notifications,
            'agent_build_temp': self._cleanup_agent_build_temp,
            'agent_update_outputs': self._cleanup_agent_update_outputs,
            'preview_cache': self._cleanup_preview_cache,
            'upload_tmp': self._cleanup_upload_tmp,
            'cleanup_logs': self._cleanup_logs,
        }

    def schedule_startup_cleanup(self) -> bool:
        with self._lock:
            if self._startup_scheduled:
                return False
            self._startup_scheduled = True
            timer = threading.Timer(self.start_delay_seconds, self._run_startup_cleanup)
            timer.name = 'server-startup-cleanup'
            timer.daemon = True
            self._startup_timer = timer

        timer.start()
        return True

    def _run_startup_cleanup(self):
        try:
            self.run_cleanup(trigger='startup')
        except Exception:
            logger.error('Server startup cleanup failed', exc_info=True)
        finally:
            with self._lock:
                self._startup_timer = None

    def run_cleanup(self, trigger: str = 'manual') -> dict:
        run_id = self._build_run_id()
        started_epoch = time.time()
        started_at = self._iso_time(started_epoch)
        item_results = []

        reference_epoch = self.startup_epoch if str(trigger or '').strip().lower() == 'startup' else started_epoch

        for raw_policy in self.cleanup_items:
            try:
                policy = self._normalize_policy(raw_policy)
                result = self._run_policy(policy, reference_epoch)
            except Exception as exc:
                policy_name = ''
                if isinstance(raw_policy, dict):
                    policy_name = str(raw_policy.get('name') or '').strip()
                result = self._new_item_result(policy_name or 'invalid_policy')
                result['errors'].append(str(exc))
            item_results.append(result)

        finished_epoch = time.time()
        summary = self._build_summary(
            run_id=run_id,
            trigger=trigger,
            started_at=started_at,
            finished_at=self._iso_time(finished_epoch),
            duration_ms=max(0, int((finished_epoch - started_epoch) * 1000)),
            item_results=item_results,
        )

        log_path = self._write_log(summary)
        summary['log_url'] = f'/api/server-cleanup/runs/{run_id}/log' if log_path else ''
        self._publish_completed(summary)
        logger.info(
            'Server cleanup completed: run_id=%s files=%s dirs=%s records=%s bytes=%s errors=%s',
            summary.get('run_id'),
            summary.get('removed_files'),
            summary.get('removed_dirs'),
            summary.get('removed_records'),
            summary.get('bytes_freed'),
            summary.get('error_count'),
        )
        return summary

    def get_log_path(self, run_id: str) -> str:
        normalized_run_id = str(run_id or '').strip()
        if not normalized_run_id or not all(ch.isalnum() or ch in {'-', '_'} for ch in normalized_run_id):
            raise FileNotFoundError('cleanup log not found')

        file_path = os.path.abspath(os.path.join(self.log_root_dir, f'{self.LOG_PREFIX}{normalized_run_id}.log'))
        if (
            os.path.normcase(os.path.dirname(file_path)) != os.path.normcase(self.log_root_dir)
            or not os.path.isfile(file_path)
        ):
            raise FileNotFoundError('cleanup log not found')
        return file_path

    def _run_policy(self, policy: dict, reference_epoch: float) -> dict:
        name = policy['name']
        scope = policy['scope']
        if scope != 'server':
            result = self._new_item_result(name)
            result['skipped'] = True
            result['skip_reason'] = f'Unsupported cleanup scope: {scope}'
            return result

        handler = self._server_handlers.get(name)
        if handler is None:
            raise ValueError(f'Unknown server cleanup item: {name}')

        cutoff_epoch = float(reference_epoch) - policy['older_than_seconds']
        result = handler(cutoff_epoch)
        result['name'] = name
        result['scope'] = scope
        result['older_than_seconds'] = policy['older_than_seconds']
        result['cutoff_at'] = self._iso_time(cutoff_epoch)
        return result

    @staticmethod
    def _normalize_policy(raw_policy: dict) -> dict:
        if not isinstance(raw_policy, dict):
            raise ValueError('Cleanup policy must be an object')

        name = str(raw_policy.get('name') or '').strip().lower()
        scope = str(raw_policy.get('scope') or 'server').strip().lower() or 'server'
        if not name:
            raise ValueError('Cleanup policy name is required')

        try:
            older_than_seconds = max(0, int(raw_policy.get('older_than_seconds') or 0))
        except (TypeError, ValueError) as exc:
            raise ValueError(f'Invalid older_than_seconds for cleanup item: {name}') from exc

        return {
            'name': name,
            'scope': scope,
            'older_than_seconds': older_than_seconds,
        }

    def _cleanup_notifications(self, cutoff_epoch: float) -> dict:
        result = self._new_item_result('notifications')
        file_path = getattr(self.notification_history_api.history_store, 'file_path', '')
        before_size = self._safe_file_size(file_path)
        cleanup_result = self.notification_history_api.cleanup_before_epoch(cutoff_epoch)
        after_size = self._safe_file_size(file_path)

        removed = cleanup_result.get('removed') if isinstance(cleanup_result, dict) else []
        removed = removed if isinstance(removed, list) else []
        result['removed_records'] = len(removed)
        result['bytes_freed'] = max(0, before_size - after_size)
        for item in removed:
            result['entries'].append({
                'kind': 'record',
                'path': f'notification:{item.get("id", "")}',
                'size': 0,
                'detail': str(item.get('title') or '').strip(),
            })
        return result

    def _cleanup_agent_build_temp(self, cutoff_epoch: float) -> dict:
        result = self._new_item_result('agent_build_temp')
        seen = set()

        for record in self.agent_output_registry.list_outputs():
            work_dir = os.path.abspath(str(record.get('work_dir') or '').strip()) if record.get('work_dir') else ''
            if not work_dir or work_dir in seen:
                continue
            seen.add(work_dir)
            if not self._is_owned_agent_work_dir(work_dir):
                continue
            if not os.path.isdir(work_dir) or not self._path_is_old_enough(work_dir, cutoff_epoch):
                continue
            self._remove_path(work_dir, result)

        return result

    def _cleanup_agent_update_outputs(self, cutoff_epoch: float) -> dict:
        result = self._new_item_result('agent_update_outputs')

        for record in list(self.agent_output_registry.list_outputs()):
            if str(record.get('source') or '').strip().lower() != 'update':
                continue
            file_name = str(record.get('file_name') or '').strip()
            if not file_name:
                continue

            file_path = os.path.abspath(os.path.join(self.agent_output_registry.output_dir, file_name))
            metadata_path = os.path.abspath(os.path.join(
                self.agent_output_registry.metadata_dir,
                f'{file_name}.json',
            ))
            age_path = metadata_path if os.path.isfile(metadata_path) else file_path
            if not self._path_is_old_enough(age_path, cutoff_epoch):
                continue

            output_size = self._safe_file_size(file_path)
            metadata_size = self._safe_file_size(metadata_path)
            try:
                self.agent_output_registry.delete_output(file_name)
            except Exception as exc:
                result['errors'].append(f'{file_path}: {exc}')
                continue

            if output_size or not os.path.exists(file_path):
                result['removed_files'] += 1
                result['bytes_freed'] += output_size
                result['entries'].append({
                    'kind': 'file',
                    'path': file_path,
                    'size': output_size,
                    'detail': 'agent update output',
                })
            if metadata_size:
                result['removed_files'] += 1
                result['bytes_freed'] += metadata_size
                result['entries'].append({
                    'kind': 'file',
                    'path': metadata_path,
                    'size': metadata_size,
                    'detail': 'agent update metadata',
                })

        return result

    def _cleanup_preview_cache(self, cutoff_epoch: float) -> dict:
        result = self._new_item_result('preview_cache')
        self._remove_old_files_recursively(self.artifact_service.previews_dir, cutoff_epoch, result)
        return result

    def _cleanup_upload_tmp(self, cutoff_epoch: float) -> dict:
        result = self._new_item_result('upload_tmp')
        root_dir = os.path.abspath(self.artifact_service.upload_tmp_dir)
        if not os.path.isdir(root_dir):
            return result

        for name in sorted(os.listdir(root_dir)):
            path = os.path.abspath(os.path.join(root_dir, name))
            if os.path.normcase(os.path.dirname(path)) != os.path.normcase(root_dir):
                continue
            if not self._path_is_old_enough(path, cutoff_epoch):
                continue
            self._remove_path(path, result)

        return result

    def _cleanup_logs(self, cutoff_epoch: float) -> dict:
        result = self._new_item_result('cleanup_logs')
        if not os.path.isdir(self.log_root_dir):
            return result

        for name in sorted(os.listdir(self.log_root_dir)):
            if not name.startswith(self.LOG_PREFIX) or not name.endswith('.log'):
                continue
            path = os.path.abspath(os.path.join(self.log_root_dir, name))
            if os.path.normcase(os.path.dirname(path)) != os.path.normcase(self.log_root_dir):
                continue
            if not self._path_is_old_enough(path, cutoff_epoch):
                continue
            self._remove_path(path, result)

        return result

    def _remove_old_files_recursively(self, root_dir: str, cutoff_epoch: float, result: dict):
        root_dir = os.path.abspath(root_dir)
        if not os.path.isdir(root_dir):
            return

        for current_root, _, files in os.walk(root_dir, topdown=False):
            for file_name in files:
                file_path = os.path.abspath(os.path.join(current_root, file_name))
                if not self._path_is_old_enough(file_path, cutoff_epoch):
                    continue
                self._remove_path(file_path, result)

    def _remove_path(self, path: str, result: dict):
        abs_path = os.path.abspath(path)
        if os.path.isfile(abs_path) or os.path.islink(abs_path):
            size = self._safe_file_size(abs_path)
            try:
                os.remove(abs_path)
            except Exception as exc:
                result['errors'].append(f'{abs_path}: {exc}')
                return
            result['removed_files'] += 1
            result['bytes_freed'] += size
            result['entries'].append({
                'kind': 'file',
                'path': abs_path,
                'size': size,
                'detail': '',
            })
            return

        if not os.path.isdir(abs_path):
            return

        files = []
        total_size = 0
        dir_count = 1
        for current_root, dir_names, names in os.walk(abs_path):
            dir_count += len(dir_names)
            for name in names:
                file_path = os.path.join(current_root, name)
                size = self._safe_file_size(file_path)
                total_size += size
                files.append((os.path.abspath(file_path), size))

        try:
            shutil.rmtree(abs_path)
        except Exception as exc:
            result['errors'].append(f'{abs_path}: {exc}')
            return

        result['removed_dirs'] += dir_count
        result['removed_files'] += len(files)
        result['bytes_freed'] += total_size
        result['entries'].append({
            'kind': 'dir',
            'path': abs_path,
            'size': total_size,
            'detail': '',
        })
        for file_path, size in files:
            result['entries'].append({
                'kind': 'file',
                'path': file_path,
                'size': size,
                'detail': '',
            })

    @staticmethod
    def _is_owned_agent_work_dir(work_dir: str) -> bool:
        try:
            abs_work_dir = os.path.abspath(work_dir)
            temp_root = os.path.abspath(tempfile.gettempdir())
            return (
                os.path.normcase(os.path.dirname(abs_work_dir)) == os.path.normcase(temp_root)
                and os.path.basename(abs_work_dir).startswith('agent_build_')
            )
        except Exception:
            return False

    @staticmethod
    def _path_is_old_enough(path: str, cutoff_epoch: float) -> bool:
        try:
            return os.path.getmtime(path) <= float(cutoff_epoch)
        except Exception:
            return False

    @staticmethod
    def _safe_file_size(path: str) -> int:
        try:
            return int(os.path.getsize(path)) if path and os.path.isfile(path) else 0
        except Exception:
            return 0

    @staticmethod
    def _new_item_result(name: str) -> dict:
        return {
            'name': name,
            'scope': 'server',
            'older_than_seconds': 0,
            'cutoff_at': '',
            'removed_files': 0,
            'removed_dirs': 0,
            'removed_records': 0,
            'bytes_freed': 0,
            'entries': [],
            'errors': [],
            'skipped': False,
            'skip_reason': '',
        }

    @staticmethod
    def _build_run_id() -> str:
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        return f'{stamp}-{uuid.uuid4().hex[:10]}'

    @staticmethod
    def _iso_time(epoch_value: float) -> str:
        return datetime.fromtimestamp(float(epoch_value), tz=timezone.utc).isoformat().replace('+00:00', 'Z')

    @staticmethod
    def _format_bytes(value: int) -> str:
        size = max(0, int(value or 0))
        if size < 1024:
            return f'{size} B'
        if size < 1024 * 1024:
            return f'{size / 1024:.1f} KB'
        if size < 1024 * 1024 * 1024:
            return f'{size / (1024 * 1024):.2f} MB'
        return f'{size / (1024 * 1024 * 1024):.2f} GB'

    def _build_summary(self, *, run_id: str, trigger: str, started_at: str, finished_at: str,
                       duration_ms: int, item_results: list[dict]) -> dict:
        return {
            'run_id': run_id,
            'trigger': str(trigger or '').strip() or 'manual',
            'started_at': started_at,
            'finished_at': finished_at,
            'duration_ms': int(duration_ms or 0),
            'items': item_results,
            'removed_files': sum(int(item.get('removed_files') or 0) for item in item_results),
            'removed_dirs': sum(int(item.get('removed_dirs') or 0) for item in item_results),
            'removed_records': sum(int(item.get('removed_records') or 0) for item in item_results),
            'bytes_freed': sum(int(item.get('bytes_freed') or 0) for item in item_results),
            'error_count': sum(len(item.get('errors') or []) for item in item_results),
        }

    def _write_log(self, summary: dict) -> str:
        run_id = summary['run_id']
        log_path = os.path.join(self.log_root_dir, f'{self.LOG_PREFIX}{run_id}.log')
        lines = [
            f'Server Cleanup Run: {run_id}',
            f'Trigger: {summary.get("trigger", "")}',
            f'Started: {summary.get("started_at", "")}',
            f'Finished: {summary.get("finished_at", "")}',
            f'Duration: {summary.get("duration_ms", 0)} ms',
            '',
            'Summary:',
            f'  Removed files: {summary.get("removed_files", 0)}',
            f'  Removed directories: {summary.get("removed_dirs", 0)}',
            f'  Removed records: {summary.get("removed_records", 0)}',
            f'  Freed size: {self._format_bytes(summary.get("bytes_freed", 0))} ({summary.get("bytes_freed", 0)} bytes)',
            f'  Errors: {summary.get("error_count", 0)}',
        ]

        for item in summary.get('items') or []:
            lines.extend([
                '',
                f'[{item.get("name", "")}]',
                f'  Scope: {item.get("scope", "")}',
                f'  Cutoff: {item.get("cutoff_at", "")}',
                f'  Older than: {item.get("older_than_seconds", 0)} seconds',
                f'  Removed files: {item.get("removed_files", 0)}',
                f'  Removed directories: {item.get("removed_dirs", 0)}',
                f'  Removed records: {item.get("removed_records", 0)}',
                f'  Freed size: {self._format_bytes(item.get("bytes_freed", 0))} ({item.get("bytes_freed", 0)} bytes)',
            ])
            if item.get('skipped'):
                lines.append(f'  Skipped: {item.get("skip_reason", "")}')
            for entry in item.get('entries') or []:
                size = int(entry.get('size') or 0)
                detail = str(entry.get('detail') or '').strip()
                suffix = f' · {detail}' if detail else ''
                lines.append(
                    f'  {str(entry.get("kind") or "item").upper()} '
                    f'{self._format_bytes(size)} · {entry.get("path", "")}{suffix}'
                )
            for error in item.get('errors') or []:
                lines.append(f'  ERROR · {error}')

        try:
            with open(log_path, 'w', encoding='utf-8') as file_obj:
                file_obj.write('\n'.join(lines))
                file_obj.write('\n')
            return log_path
        except Exception:
            logger.error('Failed to write server cleanup log: %s', log_path, exc_info=True)
            return ''

    def _publish_completed(self, summary: dict):
        if self.event_bus is None:
            return
        self.event_bus.publish('server_cleanup_completed', {
            'run_id': summary.get('run_id', ''),
            'trigger': summary.get('trigger', ''),
            'state': 'completed',
            'removed_files': summary.get('removed_files', 0),
            'removed_dirs': summary.get('removed_dirs', 0),
            'removed_records': summary.get('removed_records', 0),
            'bytes_freed': summary.get('bytes_freed', 0),
            'error_count': summary.get('error_count', 0),
            'log_url': summary.get('log_url', ''),
        })
