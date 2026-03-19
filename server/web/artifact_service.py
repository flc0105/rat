import json
import mimetypes
import os
import shutil
import threading
import uuid
from datetime import datetime
from pathlib import Path

from werkzeug.utils import secure_filename

from server.config.config import WEB_CLEAR_PREVIEW_CACHE_ON_STARTUP, WEB_FILES_ROOT_DIR, WEB_PREVIEW_TEXT_MAX_BYTES
from server.models.artifact import ArtifactRecord


class WebArtifactService:
    """
    Web Artifact 服务。

    职责：
    - 统一管理 runtime/web_files/artifacts 下的所有文件产物
    - 管理 downloads / previews / http_uploads / upload_tmp 目录结构
    - 为正式 artifact 写入 meta.json
    - 提供 artifact 查询 / 删除 / 清空 / 预览 / 下载能力
    """

    MAX_PREVIEW_TEXT_BYTES = WEB_PREVIEW_TEXT_MAX_BYTES
    ARTIFACT_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    CATEGORY_DOWNLOADS = 'downloads'
    CATEGORY_PREVIEWS = 'previews'
    CATEGORY_HTTP_UPLOADS = 'http_uploads'
    CATEGORY_UPLOAD_TMP = 'upload_tmp'

    FORMAL_CATEGORIES = {
        CATEGORY_DOWNLOADS,
        CATEGORY_PREVIEWS,
        CATEGORY_HTTP_UPLOADS,
    }

    def __init__(self):
        self.web_root_dir = WEB_FILES_ROOT_DIR
        self.artifacts_root_dir = os.path.join(self.web_root_dir, 'artifacts')
        self.downloads_dir = os.path.join(self.artifacts_root_dir, self.CATEGORY_DOWNLOADS)
        self.previews_dir = os.path.join(self.artifacts_root_dir, self.CATEGORY_PREVIEWS)
        self.upload_tmp_dir = os.path.join(self.artifacts_root_dir, self.CATEGORY_UPLOAD_TMP)
        self.http_uploads_dir = os.path.join(self.artifacts_root_dir, self.CATEGORY_HTTP_UPLOADS)
        self._lock = threading.RLock()
        self._prepare_dirs()

        if WEB_CLEAR_PREVIEW_CACHE_ON_STARTUP:
            self._clear_preview_cache_on_startup()

    # ------------------ dirs ------------------ #
    def _prepare_dirs(self):
        os.makedirs(self.artifacts_root_dir, exist_ok=True)
        os.makedirs(self.downloads_dir, exist_ok=True)
        os.makedirs(self.previews_dir, exist_ok=True)
        os.makedirs(self.upload_tmp_dir, exist_ok=True)
        os.makedirs(self.http_uploads_dir, exist_ok=True)

    def _clear_preview_cache_on_startup(self):
        """
        服务端启动时清空 previews 缓存目录，避免预览文件无限堆积
        """
        try:
            if os.path.isdir(self.previews_dir):
                shutil.rmtree(self.previews_dir, ignore_errors=True)
            os.makedirs(self.previews_dir, exist_ok=True)
        except Exception:
            pass

    # ------------------ path / name helpers ------------------ #
    def _now_text(self) -> str:
        return datetime.now().strftime(self.ARTIFACT_TIME_FORMAT)

    def _normalize_hostname(self, hostname: str) -> str:
        safe_name = secure_filename((hostname or '').strip())
        return safe_name or 'unknown_host'

    def _normalize_category(self, category: str) -> str:
        safe_name = secure_filename((category or '').strip())
        return safe_name or 'default'

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

    def _get_download_host_dir(self, hostname: str) -> str:
        return self._ensure_directory(os.path.join(self.downloads_dir, self._normalize_hostname(hostname)))

    def _get_download_meta_dir(self, hostname: str) -> str:
        return self._ensure_directory(os.path.join(self._get_download_host_dir(hostname), 'meta'))

    def _get_preview_host_dir(self, hostname: str) -> str:
        return self._ensure_directory(os.path.join(self.previews_dir, self._normalize_hostname(hostname)))

    def _get_preview_meta_dir(self, hostname: str) -> str:
        return self._ensure_directory(os.path.join(self._get_preview_host_dir(hostname), 'meta'))

    def _get_http_upload_host_dir(self, category: str, hostname: str) -> str:
        return self._ensure_directory(
            os.path.join(
                self.http_uploads_dir,
                self._normalize_category(category),
                self._normalize_hostname(hostname),
            )
        )

    def _get_http_upload_meta_dir(self, category: str, hostname: str) -> str:
        return self._ensure_directory(os.path.join(self._get_http_upload_host_dir(category, hostname), 'meta'))

    def _build_unique_path(self, directory: str, filename: str) -> str:
        base_name = os.path.basename(filename) or 'file.bin'
        stem, ext = os.path.splitext(base_name)
        candidate = os.path.join(directory, base_name)
        index = 1

        while os.path.exists(candidate):
            candidate = os.path.join(directory, f'{stem}_{index}{ext}')
            index += 1

        return candidate

    def _resolve_formal_file_and_meta_dir(self, artifact_type: str, hostname: str, category: str = '') -> tuple[str, str]:
        normalized_type = (artifact_type or '').strip()

        if normalized_type == self.CATEGORY_DOWNLOADS:
            return self._get_download_host_dir(hostname), self._get_download_meta_dir(hostname)

        if normalized_type == self.CATEGORY_PREVIEWS:
            return self._get_preview_host_dir(hostname), self._get_preview_meta_dir(hostname)

        if normalized_type == self.CATEGORY_HTTP_UPLOADS:
            return self._get_http_upload_host_dir(category, hostname), self._get_http_upload_meta_dir(category, hostname)

        raise ValueError(f'Unsupported artifact type: {artifact_type}')

    def allocate_artifact_path(self, artifact_type: str, hostname: str, original_name: str, category: str = '') -> dict:
        """
        为正式 artifact 预分配文件路径。
        仅分配路径，不写 meta。
        """
        file_dir, meta_dir = self._resolve_formal_file_and_meta_dir(artifact_type, hostname, category=category)
        stored_name = self._build_stored_filename(original_name)
        target_path = self._build_unique_path(file_dir, stored_name)
        final_stored_name = os.path.basename(target_path)

        return {
            'artifact_type': artifact_type,
            'category': category,
            'hostname': self._normalize_hostname(hostname),
            'original_name': original_name,
            'stored_name': final_stored_name,
            'file_path': target_path,
            'meta_path': os.path.join(meta_dir, f'{final_stored_name}.meta.json'),
        }

    def create_upload_temp_file(self, upload) -> tuple[str, str]:
        """
        为上传到客户端的浏览器文件创建临时落盘文件
        :return: (temp_path, safe_name)
        """
        safe_name = secure_filename(upload.filename) or 'upload.bin'
        temp_dir = os.path.join(self.upload_tmp_dir, uuid.uuid4().hex)
        os.makedirs(temp_dir, exist_ok=True)

        temp_path = os.path.join(temp_dir, safe_name)
        upload.save(temp_path)
        return temp_path, safe_name

    # ------------------ meta helpers ------------------ #
    def _build_artifact_urls(self, artifact_id: str) -> dict:
        return {
            'download_url': f'/api/artifacts/{artifact_id}/download',
            'raw_url': f'/api/artifacts/{artifact_id}/raw',
            'preview_url': f'/api/artifacts/{artifact_id}/preview',
        }

    def _build_artifact_record(
        self,
        *,
        artifact_id: str,
        artifact_type: str,
        category: str,
        hostname: str,
        original_name: str,
        stored_name: str,
        file_path: str,
        size: int,
        source_type: str = '',
        source_command_id=None,
        client_id: str = '',
        addr: str = '',
        job_id: str = '',
        job_name: str = '',
        job_key: str = '',
        related_path: str = '',
        extra: dict | None = None,
    ) -> ArtifactRecord:
        urls = self._build_artifact_urls(artifact_id)
        return ArtifactRecord(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            category=category,
            hostname=hostname,
            client_id=client_id,
            addr=addr,
            original_name=original_name,
            stored_name=stored_name,
            saved_path=file_path,
            size=int(size or 0),
            created_at=self._now_text(),
            source_type=source_type,
            source_command_id=source_command_id,
            job_id=job_id,
            job_name=job_name,
            job_key=job_key,
            related_path=related_path,
            download_url=urls['download_url'],
            raw_url=urls['raw_url'],
            preview_url=urls['preview_url'],
            extra=extra or {},
        )

    def _write_meta(self, meta_path: str, payload: dict):
        with open(meta_path, 'w', encoding='utf-8') as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False, indent=2)

    def _read_meta_file(self, meta_path: str) -> dict:
        with open(meta_path, 'r', encoding='utf-8') as file_obj:
            payload = json.load(file_obj) or {}
            if not isinstance(payload, dict):
                return {}
            return payload

    def _safe_remove_file(self, path: str):
        try:
            if os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass

    def _build_artifact_view(self, record: ArtifactRecord) -> dict:
        is_available = bool(record.saved_path) and os.path.isfile(record.saved_path)
        return record.to_view_dict(
            is_available=is_available,
            status_text='' if is_available else 'File removed'
        )

    def _finalize_registered_artifact(
        self,
        *,
        artifact_type: str,
        category: str,
        hostname: str,
        original_name: str,
        file_path: str,
        meta_path: str,
        stored_name: str,
        source_type: str = '',
        source_command_id=None,
        client_id: str = '',
        addr: str = '',
        job_id: str = '',
        job_name: str = '',
        job_key: str = '',
        related_path: str = '',
        extra: dict | None = None,
    ) -> dict:
        artifact_id = uuid.uuid4().hex
        file_size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
        record = self._build_artifact_record(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            category=category,
            hostname=hostname,
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
        self._write_meta(meta_path, record.to_meta_dict())
        return self._build_artifact_view(record)

    def register_existing_artifact(
        self,
        *,
        artifact_type: str,
        category: str,
        hostname: str,
        original_name: str,
        file_path: str,
        meta_path: str,
        stored_name: str,
        source_type: str = '',
        source_command_id=None,
        client_id: str = '',
        addr: str = '',
        job_id: str = '',
        job_name: str = '',
        job_key: str = '',
        related_path: str = '',
        extra: dict | None = None,
    ) -> dict:
        with self._lock:
            return self._finalize_registered_artifact(
                artifact_type=artifact_type,
                category=category,
                hostname=hostname,
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

    def save_http_uploaded_file(
        self,
        file,
        category: str = '',
        client_id: str = '',
        hostname: str = '',
        job_id: str = '',
        job_name: str = '',
        job_key: str = '',
    ) -> dict:
        normalized_category = (category or '').strip() or 'default'
        normalized_hostname = (hostname or '').strip() or 'unknown_host'

        allocated = self.allocate_artifact_path(
            artifact_type=self.CATEGORY_HTTP_UPLOADS,
            hostname=normalized_hostname,
            original_name=file.filename,
            category=normalized_category,
        )

        file_path = allocated['file_path']
        file.save(file_path)

        return self.register_existing_artifact(
            artifact_type=self.CATEGORY_HTTP_UPLOADS,
            category=normalized_category,
            hostname=allocated['hostname'],
            original_name=file.filename,
            file_path=file_path,
            meta_path=allocated['meta_path'],
            stored_name=allocated['stored_name'],
            source_type='http_upload',
            client_id=client_id,
            job_id=job_id,
            job_name=job_name,
            job_key=job_key,
        )

    # ------------------ query helpers ------------------ #
    def _iter_formal_meta_paths(self):
        for root, _, files in os.walk(self.artifacts_root_dir):
            for filename in files:
                if filename.endswith('.meta.json'):
                    yield os.path.join(root, filename)

    def list_artifacts(self, artifact_type: str = '', hostname: str = '') -> list[dict]:
        normalized_type = (artifact_type or '').strip()
        normalized_hostname = self._normalize_hostname(hostname) if hostname else ''

        items = []
        with self._lock:
            for meta_path in self._iter_formal_meta_paths():
                try:
                    payload = self._read_meta_file(meta_path)
                except Exception:
                    continue

                if not payload:
                    continue

                record = ArtifactRecord.from_dict(payload)

                if normalized_type and record.artifact_type != normalized_type:
                    continue

                if normalized_hostname and record.hostname != normalized_hostname:
                    continue

                items.append(self._build_artifact_view(record))

        items.sort(key=lambda item: item.get('created_at', ''), reverse=True)
        return items

    def list_artifact_hostnames(self) -> list[str]:
        names = set()
        with self._lock:
            for meta_path in self._iter_formal_meta_paths():
                try:
                    payload = self._read_meta_file(meta_path)
                except Exception:
                    continue

                record = ArtifactRecord.from_dict(payload)
                hostname = (record.hostname or '').strip()
                if hostname:
                    names.add(hostname)

        return sorted(names)

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

                record = ArtifactRecord.from_dict(payload)
                if record.artifact_id == target_id:
                    return self._build_artifact_view(record)

        raise FileNotFoundError('artifact not found')

    def get_artifact_file_path(self, artifact_id: str) -> str:
        artifact = self.get_artifact_by_id(artifact_id)
        record = ArtifactRecord.from_dict(artifact)
        if not os.path.isfile(record.saved_path):
            raise FileNotFoundError('file not found')
        return record.saved_path

    def delete_artifact(self, artifact_id: str) -> dict:
        artifact = self.get_artifact_by_id(artifact_id)
        record = ArtifactRecord.from_dict(artifact)
        self._safe_remove_file(record.saved_path)

        if record.artifact_type == self.CATEGORY_DOWNLOADS:
            meta_path = os.path.join(self._get_download_meta_dir(record.hostname), f'{record.stored_name}.meta.json')
        elif record.artifact_type == self.CATEGORY_PREVIEWS:
            meta_path = os.path.join(self._get_preview_meta_dir(record.hostname), f'{record.stored_name}.meta.json')
        elif record.artifact_type == self.CATEGORY_HTTP_UPLOADS:
            meta_path = os.path.join(self._get_http_upload_meta_dir(record.category, record.hostname), f'{record.stored_name}.meta.json')
        else:
            meta_path = ''

        self._safe_remove_file(meta_path)

        return {
            'artifact_id': record.artifact_id,
            'stored_name': record.stored_name,
            'saved_path': record.saved_path,
        }

    def clear_artifacts(self, artifact_type: str, hostname: str = '') -> dict:
        normalized_type = (artifact_type or '').strip()
        if normalized_type not in self.FORMAL_CATEGORIES:
            raise ValueError('invalid artifact type')

        items = self.list_artifacts(artifact_type=normalized_type, hostname=hostname)
        deleted_count = 0

        for item in items:
            try:
                self.delete_artifact(item.get('artifact_id', ''))
                deleted_count += 1
            except Exception:
                continue

        return {
            'artifact_type': normalized_type,
            'hostname': self._normalize_hostname(hostname) if hostname else '',
            'deleted_count': deleted_count,
        }

    # ------------------ preview helpers ------------------ #
    def guess_preview_type(self, filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()

        image_exts = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'}
        text_exts = {
            '.txt', '.log', '.py', '.js', '.ts', '.json', '.xml', '.yaml', '.yml',
            '.ini', '.cfg', '.conf', '.md', '.csv', '.sql', '.bat', '.sh', '.html', '.css'
        }

        if ext in image_exts:
            return 'image'
        if ext in text_exts:
            return 'text'

        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type:
            if mime_type.startswith('image/'):
                return 'image'
            if mime_type.startswith('text/'):
                return 'text'

        return 'unsupported'

    def build_preview_payload(self, artifact_id: str) -> dict:
        artifact = self.get_artifact_by_id(artifact_id)
        record = ArtifactRecord.from_dict(artifact)
        display_name = record.original_name or record.stored_name or 'artifact'

        if not os.path.isfile(record.saved_path):
            raise FileNotFoundError('file not found')

        preview_type = self.guess_preview_type(display_name)

        if preview_type == 'image':
            return {
                'type': 'image',
                'name': os.path.basename(display_name),
                'url': record.raw_url,
                'artifact_id': record.artifact_id,
            }

        if preview_type == 'text':
            truncated = False

            with open(record.saved_path, 'rb') as file_obj:
                raw = file_obj.read(self.MAX_PREVIEW_TEXT_BYTES + 1)

            if len(raw) > self.MAX_PREVIEW_TEXT_BYTES:
                raw = raw[:self.MAX_PREVIEW_TEXT_BYTES]
                truncated = True

            text = raw.decode('utf-8', errors='replace')
            if truncated:
                text += '\n\n...(已截断)'

            return {
                'type': 'text',
                'name': os.path.basename(display_name),
                'content': text,
                'truncated': truncated,
                'artifact_id': record.artifact_id,
            }

        return {
            'type': 'unsupported',
            'name': os.path.basename(display_name),
            'artifact_id': record.artifact_id,
        }