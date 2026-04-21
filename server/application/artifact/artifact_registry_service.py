import json
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path

from werkzeug.utils import secure_filename


class ArtifactRegistryService:
    """
    Artifact 注册/查询服务。

    当前正式 artifact 仅保留：
    - files
    - previews
    """

    ARTIFACT_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    CATEGORY_FILES = 'files'
    CATEGORY_PREVIEWS = 'previews'

    FORMAL_CATEGORIES = {
        CATEGORY_FILES,
        CATEGORY_PREVIEWS,
    }

    def __init__(self, artifact_service):
        self.artifact_service = artifact_service
        self._lock = threading.RLock()

    def _now_text(self) -> str:
        return datetime.now().strftime(self.ARTIFACT_TIME_FORMAT)

    def _normalize_machine_id(self, machine_id: str) -> str:
        safe_name = secure_filename((machine_id or '').strip())
        return safe_name or 'unknown_machine'

    def _normalize_category(self, category: str) -> str:
        safe_name = secure_filename((category or '').strip())
        return safe_name or 'default'

    def _normalize_artifact_type(self, artifact_type: str) -> str:
        normalized = (artifact_type or '').strip()
        if normalized not in self.FORMAL_CATEGORIES:
            raise ValueError(f'Unsupported artifact type: {artifact_type}')
        return normalized

    def _build_stored_filename(self, original_name: str) -> str:
        safe_name = secure_filename(original_name or '')
        if not safe_name:
            safe_name = 'unnamed_file'

        ext = Path(safe_name).suffix
        stem = Path(safe_name).stem
        unique_suffix = uuid.uuid4().hex[:8]
        return f'{stem}_{unique_suffix}{ext}'

    def _ensure_directory(self, path: str) -> str:
        os.makedirs(path, exist_ok=True)
        return path

    def _get_files_machine_dir(self, category: str, machine_id: str) -> str:
        return self._ensure_directory(
            os.path.join(
                self.artifact_service.files_dir,
                self._normalize_category(category),
                self._normalize_machine_id(machine_id),
            )
        )

    def _get_files_meta_dir(self, category: str, machine_id: str) -> str:
        return self._ensure_directory(os.path.join(self._get_files_machine_dir(category, machine_id), 'meta'))

    def _get_preview_machine_dir(self, machine_id: str) -> str:
        return self._ensure_directory(
            os.path.join(
                self.artifact_service.previews_dir,
                self._normalize_machine_id(machine_id),
            )
        )

    def _get_preview_meta_dir(self, machine_id: str) -> str:
        return self._ensure_directory(os.path.join(self._get_preview_machine_dir(machine_id), 'meta'))

    def _build_unique_path(self, directory: str, filename: str) -> str:
        base_name = os.path.basename(filename) or 'file.bin'
        stem, ext = os.path.splitext(base_name)
        candidate = os.path.join(directory, base_name)
        index = 1
        while os.path.exists(candidate):
            candidate = os.path.join(directory, f'{stem}_{index}{ext}')
            index += 1
        return candidate

    def _resolve_formal_file_and_meta_dir(self, artifact_type: str, machine_id: str, category: str = '') -> tuple[str, str]:
        normalized_type = self._normalize_artifact_type(artifact_type)
        if normalized_type == self.CATEGORY_FILES:
            return self._get_files_machine_dir(category, machine_id), self._get_files_meta_dir(category, machine_id)
        if normalized_type == self.CATEGORY_PREVIEWS:
            return self._get_preview_machine_dir(machine_id), self._get_preview_meta_dir(machine_id)
        raise ValueError(f'Unsupported artifact type: {artifact_type}')

    def allocate_artifact_path(self, artifact_type: str, machine_id: str, original_name: str, category: str = '') -> dict:
        normalized_type = self._normalize_artifact_type(artifact_type)
        file_dir, meta_dir = self._resolve_formal_file_and_meta_dir(normalized_type, machine_id, category=category)
        stored_name = self._build_stored_filename(original_name)
        target_path = self._build_unique_path(file_dir, stored_name)
        final_stored_name = os.path.basename(target_path)
        return {
            'artifact_type': normalized_type,
            'category': category,
            'machine_id': self._normalize_machine_id(machine_id),
            'original_name': original_name,
            'stored_name': final_stored_name,
            'file_path': target_path,
            'meta_path': os.path.join(meta_dir, f'{final_stored_name}.meta.json'),
        }

    def _build_artifact_urls(self, artifact_id: str) -> dict:
        return {
            'download_url': f'/api/artifacts/{artifact_id}/download',
            'raw_url': f'/api/artifacts/{artifact_id}/raw',
            'preview_url': f'/api/artifacts/{artifact_id}/preview',
        }

    def _build_meta_payload(self, *, artifact_id: str, artifact_type: str, category: str, hostname: str, machine_id: str,
                            original_name: str, stored_name: str, file_path: str, size: int, source_type: str = '',
                            source_command_id=None, client_id: str = '', addr: str = '', job_id: str = '',
                            job_name: str = '', job_key: str = '', related_path: str = '', extra: dict | None = None) -> dict:
        payload = {
            'artifact_id': artifact_id,
            'artifact_type': self._normalize_artifact_type(artifact_type),
            'category': category,
            'hostname': hostname,
            'machine_id': machine_id,
            'client_id': client_id,
            'addr': addr,
            'original_name': original_name,
            'stored_name': stored_name,
            'saved_path': file_path,
            'size': int(size or 0),
            'created_at': self._now_text(),
            'source_type': source_type,
            'source_command_id': source_command_id,
            'job_id': job_id,
            'job_name': job_name,
            'job_key': job_key,
            'related_path': related_path,
        }
        payload.update(self._build_artifact_urls(artifact_id))
        if isinstance(extra, dict):
            payload['extra'] = extra
        return payload

    def _write_meta(self, meta_path: str, payload: dict):
        with open(meta_path, 'w', encoding='utf-8') as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False, indent=2)

    def _read_meta_file(self, meta_path: str) -> dict:
        with open(meta_path, 'r', encoding='utf-8') as file_obj:
            payload = json.load(file_obj) or {}
            if not isinstance(payload, dict):
                return {}
            payload['_meta_path'] = meta_path
            return payload

    def _safe_remove_file(self, path: str):
        try:
            if os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass

    def _finalize_registered_artifact(self, *, artifact_type: str, category: str, hostname: str, machine_id: str,
                                      original_name: str, file_path: str, meta_path: str, stored_name: str,
                                      source_type: str = '', source_command_id=None, client_id: str = '', addr: str = '',
                                      job_id: str = '', job_name: str = '', job_key: str = '', related_path: str = '',
                                      extra: dict | None = None) -> dict:
        artifact_id = uuid.uuid4().hex
        file_size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
        meta = self._build_meta_payload(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            category=category,
            hostname=hostname,
            machine_id=machine_id,
            original_name=original_name,
            stored_name=stored_name,
            file_path=file_path,
            size=file_size,
            source_type=source_type,
            source_command_id=source_command_id,
            client_id=client_id,
            addr=addr,
            job_id=job_id,
            job_name=job_name,
            job_key=job_key,
            related_path=related_path,
            extra=extra,
        )
        self._write_meta(meta_path, meta)
        meta['_meta_path'] = meta_path
        return meta

    def register_existing_artifact(self, *, artifact_type: str, category: str, hostname: str, machine_id: str,
                                   original_name: str, file_path: str, meta_path: str, stored_name: str,
                                   source_type: str = '', source_command_id=None, client_id: str = '', addr: str = '',
                                   job_id: str = '', job_name: str = '', job_key: str = '', related_path: str = '',
                                   extra: dict | None = None) -> dict:
        with self._lock:
            return self._finalize_registered_artifact(
                artifact_type=artifact_type,
                category=category,
                hostname=hostname,
                machine_id=machine_id,
                original_name=original_name,
                file_path=file_path,
                meta_path=meta_path,
                stored_name=stored_name,
                source_type=source_type,
                source_command_id=source_command_id,
                client_id=client_id,
                addr=addr,
                job_id=job_id,
                job_name=job_name,
                job_key=job_key,
                related_path=related_path,
                extra=extra,
            )

    def save_http_uploaded_file(self, file, artifact_type: str = '', category: str = '', client_id: str = '',
                                hostname: str = '', machine_id: str = '', job_id: str = '', job_name: str = '',
                                job_key: str = '', source_type: str = '', source_command_id=None, addr: str = '',
                                related_path: str = '', extra: dict | None = None) -> dict:
        normalized_type = self._normalize_artifact_type(artifact_type or self.CATEGORY_FILES)
        normalized_category = (category or '').strip() or 'default'
        normalized_hostname = (hostname or '').strip() or 'unknown_host'
        normalized_machine_id = (machine_id or '').strip() or 'unknown_machine'
        allocated = self.allocate_artifact_path(
            artifact_type=normalized_type,
            machine_id=normalized_machine_id,
            original_name=file.filename,
            category=normalized_category,
        )
        file_path = allocated['file_path']
        file.save(file_path)
        return self.register_existing_artifact(
            artifact_type=normalized_type,
            category=normalized_category,
            hostname=normalized_hostname,
            machine_id=allocated['machine_id'],
            original_name=file.filename,
            file_path=file_path,
            meta_path=allocated['meta_path'],
            stored_name=allocated['stored_name'],
            source_type=source_type or 'client_upload',
            source_command_id=source_command_id,
            client_id=client_id,
            addr=addr,
            job_id=job_id,
            job_name=job_name,
            job_key=job_key,
            related_path=related_path,
            extra=extra,
        )

    def _iter_formal_meta_paths(self):
        search_roots = [self.artifact_service.files_dir, self.artifact_service.previews_dir]
        for root_dir in search_roots:
            if not os.path.isdir(root_dir):
                continue
            for root, _, files in os.walk(root_dir):
                for filename in files:
                    if filename.endswith('.meta.json'):
                        yield os.path.join(root, filename)

    def _normalize_meta_for_view(self, payload: dict) -> dict:
        item = dict(payload)
        saved_path = item.get('saved_path', '')
        item['is_available'] = bool(saved_path) and os.path.isfile(saved_path)
        item['status_text'] = '' if item['is_available'] else 'File removed'
        return item

    def list_artifacts(self, artifact_type: str = '', machine_id: str = '') -> list[dict]:
        normalized_type = self._normalize_artifact_type(artifact_type) if artifact_type else ''
        normalized_machine_id = self._normalize_machine_id(machine_id) if machine_id else ''
        items = []
        with self._lock:
            for meta_path in self._iter_formal_meta_paths():
                try:
                    payload = self._read_meta_file(meta_path)
                except Exception:
                    continue
                if not payload:
                    continue
                view_payload = self._normalize_meta_for_view(payload)
                if normalized_type and view_payload.get('artifact_type') != normalized_type:
                    continue
                if normalized_machine_id and view_payload.get('machine_id') != normalized_machine_id:
                    continue
                items.append(view_payload)
        items.sort(key=lambda item: item.get('created_at', ''), reverse=True)
        return items

    def list_artifact_machines(self) -> list[dict]:
        items = {}
        with self._lock:
            for meta_path in self._iter_formal_meta_paths():
                try:
                    payload = self._read_meta_file(meta_path)
                except Exception:
                    continue
                machine_id = (payload.get('machine_id') or '').strip()
                if not machine_id:
                    continue
                existing = items.get(machine_id) or {}
                items[machine_id] = {
                    'machine_id': machine_id,
                    'hostname': (payload.get('hostname') or existing.get('hostname') or '').strip(),
                }
        return sorted(items.values(), key=lambda item: (item.get('hostname') or item.get('machine_id') or '').lower())

    def get_artifact_by_id(self, artifact_id: str) -> dict:
        target_id = (artifact_id or '').strip()
        if not target_id:
            raise FileNotFoundError('artifact not found')
        with self._lock:
            for meta_path in self._iter_formal_meta_paths():
                try:
                    payload = self._read_meta_file(meta_path)
                except Exception:
                    continue
                if payload.get('artifact_id') == target_id:
                    return self._normalize_meta_for_view(payload)
        raise FileNotFoundError('artifact not found')

    def get_artifact_file_path(self, artifact_id: str) -> str:
        artifact = self.get_artifact_by_id(artifact_id)
        file_path = artifact.get('saved_path', '')
        if not os.path.isfile(file_path):
            raise FileNotFoundError('file not found')
        return file_path

    def delete_artifact(self, artifact_id: str) -> dict:
        artifact = self.get_artifact_by_id(artifact_id)
        self._safe_remove_file(artifact.get('saved_path', ''))
        self._safe_remove_file(artifact.get('_meta_path', ''))
        return {
            'artifact_id': artifact.get('artifact_id', ''),
            'stored_name': artifact.get('stored_name', ''),
            'saved_path': artifact.get('saved_path', ''),
        }

    def clear_artifacts(self, artifact_type: str, machine_id: str = '') -> dict:
        normalized_type = self._normalize_artifact_type(artifact_type)
        items = self.list_artifacts(artifact_type=normalized_type, machine_id=machine_id)
        deleted_count = 0
        for item in items:
            try:
                self.delete_artifact(item.get('artifact_id', ''))
                deleted_count += 1
            except Exception:
                continue
        return {
            'artifact_type': normalized_type,
            'machine_id': self._normalize_machine_id(machine_id) if machine_id else '',
            'deleted_count': deleted_count,
        }
