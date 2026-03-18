import json
import mimetypes
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from werkzeug.utils import secure_filename


class WebFileService:
    """
    Web 文件服务。

    职责：
    - 管理 Web 文件目录
    - 管理最近接收文件列表
    - 提供文件安全路径解析
    - 提供文件预览能力
    - 删除接收文件
    - 处理上传到客户端前的临时落盘
    - 处理 HTTP 上传文件的正式落盘
    """

    MAX_PREVIEW_TEXT_BYTES = 200 * 1024

    def __init__(self):
        self.web_root_dir = os.path.abspath(os.path.join('runtime', 'web_files'))
        self.received_files_dir = os.path.join(self.web_root_dir, 'received')
        self.preview_files_dir = os.path.join(self.web_root_dir, 'preview')
        self.upload_tmp_dir = os.path.join(self.web_root_dir, 'upload_tmp')
        self.http_uploads_dir = os.path.join(self.web_root_dir, 'http_uploads')
        self._prepare_dirs()
        self._clear_preview_cache_on_startup()

    # ------------------ dirs ------------------ #
    def _prepare_dirs(self):
        os.makedirs(self.received_files_dir, exist_ok=True)
        os.makedirs(self.preview_files_dir, exist_ok=True)
        os.makedirs(self.upload_tmp_dir, exist_ok=True)
        os.makedirs(self.http_uploads_dir, exist_ok=True)

    def _clear_preview_cache_on_startup(self):
        """
        服务端启动时清空 preview 缓存目录，避免预览文件无限堆积
        """
        try:
            if os.path.isdir(self.preview_files_dir):
                shutil.rmtree(self.preview_files_dir, ignore_errors=True)
            os.makedirs(self.preview_files_dir, exist_ok=True)
        except Exception:
            pass

    # ------------------ received files ------------------ #
    def list_received_files(self):
        items = []
        directory = self.received_files_dir

        if not os.path.isdir(directory):
            return items

        for name in os.listdir(directory):
            path = os.path.join(directory, name)

            if not os.path.isfile(path):
                continue

            if name.endswith('.meta.json'):
                continue

            stat = os.stat(path)
            meta_path = path + '.meta.json'
            meta = {}

            if os.path.isfile(meta_path):
                try:
                    with open(meta_path, 'r', encoding='utf-8') as f:
                        meta = json.load(f) or {}
                except Exception:
                    meta = {}

            items.append({
                'client_id': meta.get('client_id', ''),
                'hostname': meta.get('hostname', ''),
                'addr': meta.get('addr', ''),
                'original_name': meta.get('original_name', name),
                'saved_name': name,
                'size': meta.get('size', stat.st_size),
                'created_at': meta.get('created_at') or datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'download_url': f'/api/files/recent/{name}'
            })

        items.sort(key=lambda x: x['created_at'], reverse=True)
        return items

    def get_received_file_download_path(self, saved_name: str) -> str:
        return os.path.join(self.received_files_dir, saved_name)

    def get_safe_received_file_path(self, saved_name: str) -> str:
        base_dir = os.path.abspath(self.received_files_dir)
        file_path = os.path.abspath(os.path.join(base_dir, saved_name))
        if not file_path.startswith(base_dir + os.sep) and file_path != base_dir:
            raise ValueError('invalid file path')
        return file_path

    # ------------------ preview files ------------------ #
    def get_preview_dir_for_hostname(self, hostname: str = '') -> str:
        safe_host = secure_filename(hostname or 'unknown_host') or 'unknown_host'
        target_dir = os.path.join(self.preview_files_dir, safe_host)
        os.makedirs(target_dir, exist_ok=True)
        return target_dir

    def get_safe_preview_file_path(self, relative_path: str) -> str:
        base_dir = os.path.abspath(self.preview_files_dir)
        file_path = os.path.abspath(os.path.join(base_dir, relative_path))
        if not file_path.startswith(base_dir + os.sep) and file_path != base_dir:
            raise ValueError('invalid preview file path')
        return file_path

    def build_preview_relative_path(self, hostname: str, saved_name: str) -> str:
        safe_host = secure_filename(hostname or 'unknown_host') or 'unknown_host'
        safe_name = os.path.basename(saved_name)
        return os.path.join(safe_host, safe_name).replace('\\', '/')

    # ------------------ preview helpers ------------------ #
    def guess_preview_type(self, filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()

        image_exts = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'}
        text_exts = {
            '.txt', '.log', '.py', '.js', '.ts', '.json', '.xml', '.yaml', '.yml',
            '.ini', '.cfg', '.conf', '.md', '.csv', '.sql', '.bat', '.sh'
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

    def _build_preview_payload_from_path(self, file_path: str, display_name: str, raw_url: str) -> dict:
        if not os.path.isfile(file_path):
            raise FileNotFoundError('file not found')

        preview_type = self.guess_preview_type(display_name)

        if preview_type == 'image':
            return {
                'type': 'image',
                'name': os.path.basename(display_name),
                'url': raw_url
            }

        if preview_type == 'text':
            truncated = False

            with open(file_path, 'rb') as f:
                raw = f.read(self.MAX_PREVIEW_TEXT_BYTES + 1)

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
                'truncated': truncated
            }

        return {
            'type': 'unsupported',
            'name': os.path.basename(display_name)
        }

    def build_file_preview_payload(self, saved_name: str) -> dict:
        file_path = self.get_safe_received_file_path(saved_name)
        return self._build_preview_payload_from_path(
            file_path=file_path,
            display_name=saved_name,
            raw_url=f'/api/files/recent/{saved_name}/raw'
        )

    def build_preview_file_payload(self, relative_path: str) -> dict:
        file_path = self.get_safe_preview_file_path(relative_path)
        return self._build_preview_payload_from_path(
            file_path=file_path,
            display_name=os.path.basename(relative_path),
            raw_url=f'/api/files/preview/{relative_path}/raw'
        )

    def delete_received_file(self, saved_name: str) -> None:
        file_path = self.get_safe_received_file_path(saved_name)

        if not os.path.isfile(file_path):
            raise FileNotFoundError('file not found')

        meta_path = file_path + '.meta.json'
        os.remove(file_path)
        if os.path.isfile(meta_path):
            os.remove(meta_path)

    # ------------------ temp upload ------------------ #
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

    # ------------------ http uploads ------------------ #
    def build_stored_filename(self, original_name: str) -> str:
        safe_name = secure_filename(original_name)
        if not safe_name:
            safe_name = 'unnamed_file'

        ext = Path(safe_name).suffix
        stem = Path(safe_name).stem
        unique_suffix = uuid.uuid4().hex[:8]
        return f'{stem}_{unique_suffix}{ext}'

    def save_http_uploaded_file(self, file, category: str = '', client_id: str = '') -> dict:
        target_dir = Path(self.http_uploads_dir)
        if category:
            target_dir = target_dir / secure_filename(category)
        if client_id:
            target_dir = target_dir / secure_filename(client_id)

        target_dir.mkdir(parents=True, exist_ok=True)

        stored_name = self.build_stored_filename(file.filename)
        stored_path = target_dir / stored_name
        file.save(stored_path)

        file_size = stored_path.stat().st_size

        return {
            'ok': True,
            'original_name': file.filename,
            'stored_name': stored_name,
            'size': file_size,
            'category': category,
            'client_id': client_id,
        }