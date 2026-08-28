import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

import requests
from PIL import Image

from client.clipboard.adapters.macos import MacOSClipboardAdapter
from client.clipboard.adapters.unsupported import UnsupportedClipboardAdapter
from client.clipboard.adapters.windows import WindowsClipboardAdapter
from client.config.config import CLIPBOARD_STAGING_DIR
from client.http.client_api import ClientApiClient
from core.protocol.message_types import MSG_TYPE_CLIPBOARD_RESULT


class ClipboardManager:
    def __init__(self, connection):
        self.connection = connection
        self.client_api = ClientApiClient()
        self.staging_dir = os.path.abspath(os.path.expanduser(CLIPBOARD_STAGING_DIR))
        self.adapter = self._build_adapter()
        self._clear_staging_on_startup()

    def _build_adapter(self):
        if sys.platform == 'win32':
            return WindowsClipboardAdapter()
        if sys.platform == 'darwin':
            return MacOSClipboardAdapter()
        return UnsupportedClipboardAdapter(sys.platform)

    def get_capabilities(self) -> dict:
        caps = self.adapter.get_capabilities()
        return {
            'platform': sys.platform,
            'text': bool(caps.get('text')),
            'image': bool(caps.get('image')),
            'files': bool(caps.get('files')),
        }

    def handle_get(self, request_id: str, mode: str = 'content'):
        request_id = str(request_id or '').strip()
        if not request_id:
            return
        try:
            if str(mode or '').strip().lower() == 'capabilities':
                payload = {'kind': 'capabilities', 'capabilities': self.get_capabilities()}
            else:
                payload = self._materialize_snapshot(self.adapter.get_snapshot())
                payload['capabilities'] = self.get_capabilities()
            self._send_result(request_id, 'get', True, payload=payload)
        except Exception as e:
            self._send_result(request_id, 'get', False, error=str(e))

    def handle_set(self, request_id: str, payload: dict):
        request_id = str(request_id or '').strip()
        if not request_id:
            return
        try:
            normalized = payload if isinstance(payload, dict) else {}
            kind = str(normalized.get('kind') or '').strip().lower()
            if kind == 'text':
                self.adapter.set_text(str(normalized.get('text') or ''))
            elif kind == 'image':
                items = normalized.get('items') if isinstance(normalized.get('items'), list) else []
                paths = self._download_staged_items(request_id, items)
                if not paths:
                    raise ValueError('Image payload is empty')
                self.adapter.set_image(paths[0])
            elif kind == 'files':
                items = normalized.get('items') if isinstance(normalized.get('items'), list) else []
                paths = self._download_staged_items(request_id, items)
                if not paths:
                    raise ValueError('File payload is empty')
                self.adapter.set_files(paths)
            else:
                raise ValueError(f'Unsupported clipboard payload: {kind or "empty"}')
            self._send_result(
                request_id,
                'set',
                True,
                payload={'kind': kind, 'capabilities': self.get_capabilities()},
            )
        except Exception as e:
            self._send_result(request_id, 'set', False, error=str(e))

    def _materialize_snapshot(self, snapshot: dict) -> dict:
        kind = str((snapshot or {}).get('kind') or 'empty').strip().lower()
        if kind == 'text':
            return {'kind': 'text', 'text': str(snapshot.get('text') or '')}
        if kind == 'image':
            raw = snapshot.get('data') or b''
            if not raw:
                return {'kind': 'empty'}
            image_format = str(snapshot.get('format') or 'png').lower()
            if image_format != 'png':
                raw = self._convert_image_to_png(raw)
            artifact = self._upload_bytes_artifact(
                raw,
                filename=f'clipboard_{uuid.uuid4().hex[:8]}.png',
                category='clipboard_image',
                extra={'clipboard_kind': 'image'},
            )
            return {'kind': 'image', 'artifact': artifact}
        if kind == 'files':
            paths = snapshot.get('paths') if isinstance(snapshot.get('paths'), list) else []
            artifacts = []
            for path in paths:
                if not path or not os.path.exists(path):
                    continue
                artifacts.append(self._upload_clipboard_path(path))
            return {'kind': 'files', 'artifacts': artifacts}
        return {'kind': 'empty'}

    def _upload_clipboard_path(self, path: str) -> dict:
        abs_path = os.path.abspath(path)
        cleanup_path = ''
        upload_path = abs_path
        display_name = os.path.basename(abs_path.rstrip(os.sep)) or 'clipboard_file'
        extra = {
            'clipboard_kind': 'file',
            'source_path': abs_path,
            'source_is_directory': os.path.isdir(abs_path),
        }
        try:
            if os.path.isdir(abs_path):
                temp_dir = tempfile.mkdtemp(prefix='rch_clipboard_dir_')
                archive_base = os.path.join(temp_dir, display_name)
                upload_path = shutil.make_archive(archive_base, 'zip', root_dir=os.path.dirname(abs_path), base_dir=os.path.basename(abs_path))
                cleanup_path = temp_dir
                display_name = f'{display_name}.zip'
            return self._upload_file_artifact(
                upload_path,
                filename=display_name,
                category='clipboard_file',
                extra=extra,
            )
        finally:
            if cleanup_path:
                shutil.rmtree(cleanup_path, ignore_errors=True)

    def _upload_bytes_artifact(self, data: bytes, *, filename: str, category: str, extra: dict) -> dict:
        temp_dir = tempfile.mkdtemp(prefix='rch_clipboard_upload_')
        try:
            path = os.path.join(temp_dir, filename)
            with open(path, 'wb') as file_obj:
                file_obj.write(data)
            return self._upload_file_artifact(path, filename=filename, category=category, extra=extra)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _upload_file_artifact(self, path: str, *, filename: str, category: str, extra: dict) -> dict:
        client_id = str(getattr(self.connection, 'client_id', '') or '')
        form = {
            'artifact_type': 'files',
            'category': category,
            'client_id': client_id,
            'extra': json.dumps(extra or {}, ensure_ascii=False),
        }
        with open(path, 'rb') as file_obj:
            response = requests.post(
                self.client_api.build_file_upload_url(),
                files={'file': (filename, file_obj)},
                data=form,
                timeout=(15, 60 * 60),
            )
        payload = self.client_api.parse_json_response(response)
        data = payload.get('data') if isinstance(payload, dict) else None
        if not isinstance(data, dict) or not data.get('artifact_id'):
            raise RuntimeError('Clipboard artifact upload did not return artifact metadata')
        return data

    def _download_staged_items(self, request_id: str, items: list[dict]) -> list[str]:
        request_dir = os.path.join(self.staging_dir, self._safe_component(request_id))
        os.makedirs(request_dir, exist_ok=True)
        paths = []
        used_names = set()
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            url = str(item.get('url') or '').strip()
            if not url:
                continue
            original = self._safe_component(item.get('name') or f'clipboard_{index + 1}.bin')
            name = self._unique_name(original, used_names)
            used_names.add(name)
            target_path = os.path.join(request_dir, name)
            self.client_api.download_file(url, target_path, timeout=(15, 60 * 60))
            paths.append(target_path)
        return paths

    def _clear_staging_on_startup(self):
        try:
            if os.path.isdir(self.staging_dir):
                shutil.rmtree(self.staging_dir, ignore_errors=True)
            os.makedirs(self.staging_dir, exist_ok=True)
        except Exception:
            pass

    def _send_result(self, request_id: str, operation: str, ok: bool, *, payload=None, error: str = ''):
        self.connection.send({
            'type': MSG_TYPE_CLIPBOARD_RESULT,
            'clipboard_request_id': request_id,
            'operation': operation,
            'ok': bool(ok),
            'payload': payload if isinstance(payload, dict) else {},
            'error': str(error or ''),
        })

    @staticmethod
    def _convert_image_to_png(raw: bytes) -> bytes:
        import io
        image = Image.open(io.BytesIO(raw))
        output = io.BytesIO()
        image.save(output, format='PNG')
        return output.getvalue()

    @staticmethod
    def _safe_component(value: str) -> str:
        value = os.path.basename(str(value or '').strip().replace('\\', '/'))
        return ''.join(ch for ch in value if ch not in '<>:"/\\|?*\x00') or 'clipboard_item'

    @staticmethod
    def _unique_name(name: str, used_names: set[str]) -> str:
        if name not in used_names:
            return name
        stem, ext = os.path.splitext(name)
        index = 1
        while f'{stem}_{index}{ext}' in used_names:
            index += 1
        return f'{stem}_{index}{ext}'
