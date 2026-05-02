import json
import os
import tempfile
import threading
import uuid
from datetime import datetime

from core.utils.files import secure_filename
from server.config.config import KEYCHAINS_ROOT_DIR


class KeychainStore:
    """
    服务端凭证 JSON 存储。

    职责：
    - 按 machine_id 保存凭证列表
    - 提供凭证创建 / 更新 / 删除 / 查看
    - 列表接口默认隐藏 secret_value，查看时再返回明文
    """

    SERVER_MACHINE_ID = '__server__'
    SERVER_HOSTNAME = 'Server'
    TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    KIND_LOGIN = 'login'
    KIND_SECRET = 'secret'

    MAX_TEXT_CHARS = 4096
    MAX_SECRET_CHARS = 256 * 1024

    def __init__(self):
        self.root_dir = KEYCHAINS_ROOT_DIR
        self._lock = threading.RLock()
        self._prepare_dirs()

    def _prepare_dirs(self):
        os.makedirs(self.root_dir, exist_ok=True)

    def _now_text(self) -> str:
        return datetime.now().strftime(self.TIME_FORMAT)

    def _safe_text(self, value, max_chars: int = MAX_TEXT_CHARS) -> str:
        text = '' if value is None else str(value)
        text = text.strip()
        if max_chars > 0 and len(text) > max_chars:
            return text[:max_chars]
        return text

    def _normalize_machine_id(self, machine_id: str) -> str:
        value = self._safe_text(machine_id)
        return value or self.SERVER_MACHINE_ID

    def _normalize_hostname(self, machine_id: str, hostname: str) -> str:
        normalized_machine_id = self._normalize_machine_id(machine_id)
        if normalized_machine_id == self.SERVER_MACHINE_ID:
            return self.SERVER_HOSTNAME
        return self._safe_text(hostname) or 'Unknown'

    def _normalize_file_stem(self, machine_id: str) -> str:
        safe_name = secure_filename(self._normalize_machine_id(machine_id))
        return safe_name or self.SERVER_MACHINE_ID

    def _get_file_path(self, machine_id: str) -> str:
        normalized = self._normalize_file_stem(machine_id)
        return os.path.join(self.root_dir, f'{normalized}.json')

    def _normalize_kind(self, value: str) -> str:
        kind = self._safe_text(value).lower()
        if kind not in {self.KIND_LOGIN, self.KIND_SECRET}:
            return self.KIND_LOGIN
        return kind

    def _extract_secret_value(self, item: dict, kind: str) -> str:
        if kind == self.KIND_LOGIN:
            value = item.get('secret_value')
            if value is None:
                value = item.get('password')
            return self._safe_text(value, self.MAX_SECRET_CHARS)

        value = item.get('secret_value')
        if value is None:
            value = item.get('value')
        return self._safe_text(value, self.MAX_SECRET_CHARS)

    def _normalize_entry(self, item, default_machine_id: str = '') -> dict | None:
        if not isinstance(item, dict):
            return None

        now_text = self._now_text()
        machine_id = self._normalize_machine_id(item.get('machine_id') or default_machine_id)
        kind = self._normalize_kind(item.get('kind'))
        name = self._safe_text(item.get('name') or item.get('cred_name'))
        if not name:
            return None

        created_at = self._safe_text(item.get('created_at')) or now_text
        updated_at = self._safe_text(item.get('updated_at')) or created_at or now_text
        secret_value = self._extract_secret_value(item, kind)

        if kind == self.KIND_LOGIN:
            username = self._safe_text(item.get('username'))
            if not username:
                return None
            return {
                'cred_id': self._safe_text(item.get('cred_id')) or uuid.uuid4().hex,
                'machine_id': machine_id,
                'hostname': self._normalize_hostname(machine_id, item.get('hostname')),
                'kind': kind,
                'name': name,
                'username': username,
                'secret_value': secret_value,
                'site': self._safe_text(item.get('site')),
                'note': self._safe_text(item.get('note')),
                'created_at': created_at,
                'updated_at': updated_at,
            }

        return {
            'cred_id': self._safe_text(item.get('cred_id')) or uuid.uuid4().hex,
            'machine_id': machine_id,
            'hostname': self._normalize_hostname(machine_id, item.get('hostname')),
            'kind': kind,
            'name': name,
            'secret_value': secret_value,
            'note': self._safe_text(item.get('note')),
            'created_at': created_at,
            'updated_at': updated_at,
        }

    def _read_payload(self, machine_id: str) -> list[dict]:
        file_path = self._get_file_path(machine_id)
        if not os.path.isfile(file_path):
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as file_obj:
                payload = json.load(file_obj)
        except Exception:
            return []

        if isinstance(payload, dict):
            items = payload.get('items') or []
            payload_machine_id = payload.get('machine_id') or machine_id
        else:
            items = payload
            payload_machine_id = machine_id

        if not isinstance(items, list):
            return []

        normalized_items = []
        for item in items:
            normalized = self._normalize_entry(item, default_machine_id=payload_machine_id)
            if normalized:
                normalized_items.append(normalized)
        return normalized_items

    def _write_payload(self, machine_id: str, items: list[dict]):
        normalized_machine_id = self._normalize_machine_id(machine_id)
        file_path = self._get_file_path(normalized_machine_id)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        payload = {
            'machine_id': normalized_machine_id,
            'items': items,
        }

        fd, temp_path = tempfile.mkstemp(
            prefix='keychains_',
            suffix='.tmp',
            dir=os.path.dirname(file_path),
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as file_obj:
                json.dump(payload, file_obj, ensure_ascii=False, indent=2)
            os.replace(temp_path, file_path)
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

    def _list_payload_files(self) -> list[str]:
        if not os.path.isdir(self.root_dir):
            return []

        file_paths = []
        for name in os.listdir(self.root_dir):
            if not name.endswith('.json'):
                continue
            file_path = os.path.join(self.root_dir, name)
            if os.path.isfile(file_path):
                file_paths.append(file_path)
        return file_paths

    def _read_machine_id_from_file(self, file_path: str) -> str:
        try:
            with open(file_path, 'r', encoding='utf-8') as file_obj:
                payload = json.load(file_obj)
            if isinstance(payload, dict):
                machine_id = self._safe_text(payload.get('machine_id'))
                if machine_id:
                    return machine_id
        except Exception:
            pass

        return os.path.splitext(os.path.basename(file_path))[0]

    def _read_all_items_unlocked(self) -> list[dict]:
        items = []
        for file_path in self._list_payload_files():
            machine_id = self._read_machine_id_from_file(file_path)
            items.extend(self._read_payload(machine_id))
        return items

    def _find_item_unlocked(self, cred_id: str) -> tuple[str, dict | None, list[dict]]:
        cred_id_text = self._safe_text(cred_id)
        if not cred_id_text:
            return '', None, []

        for file_path in self._list_payload_files():
            machine_id = self._read_machine_id_from_file(file_path)
            items = self._read_payload(machine_id)
            for item in items:
                if item.get('cred_id') == cred_id_text:
                    return machine_id, item, items
        return '', None, []

    def _ensure_unique_name(self, items: list[dict], name: str, skip_cred_id: str = ''):
        normalized_name = self._safe_text(name).lower()
        skip_id = self._safe_text(skip_cred_id)
        for item in items:
            if skip_id and item.get('cred_id') == skip_id:
                continue
            if self._safe_text(item.get('name')).lower() == normalized_name:
                raise ValueError(f'Credential already exists: {name}')

    def _to_public_item(self, item: dict) -> dict:
        result = dict(item)
        secret_value = result.pop('secret_value', '')
        result['has_secret'] = bool(secret_value)
        result['secret_placeholder'] = '••••••••'
        return result

    def public_item(self, item: dict) -> dict:
        return self._to_public_item(item)

    def list_items(self, machine_id: str = '', reveal: bool = False) -> list[dict]:
        machine_id_text = self._safe_text(machine_id)
        with self._lock:
            if machine_id_text:
                items = self._read_payload(machine_id_text)
            else:
                items = self._read_all_items_unlocked()

        items = sorted(
            items,
            key=lambda item: (item.get('updated_at') or item.get('created_at') or '', item.get('name') or ''),
            reverse=True,
        )
        if reveal:
            return [dict(item) for item in items]
        return [self._to_public_item(item) for item in items]

    def list_stored_machines(self) -> list[dict]:
        machines = {}
        with self._lock:
            all_items = self._read_all_items_unlocked()

        for item in all_items:
            machine_id = self._normalize_machine_id(item.get('machine_id'))
            machines[machine_id] = {
                'machine_id': machine_id,
                'hostname': self._normalize_hostname(machine_id, item.get('hostname')),
            }

        return sorted(
            machines.values(),
            key=lambda item: (item.get('machine_id') != self.SERVER_MACHINE_ID, item.get('hostname') or ''),
        )

    def get_item(self, cred_id: str, reveal: bool = True) -> dict:
        with self._lock:
            _, item, _ = self._find_item_unlocked(cred_id)

        if item is None:
            raise FileNotFoundError('Credential not found')
        return dict(item) if reveal else self._to_public_item(item)

    def create_item(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError('payload is required')

        now_text = self._now_text()
        item = dict(payload)
        item['cred_id'] = uuid.uuid4().hex
        item['created_at'] = now_text
        item['updated_at'] = now_text
        normalized_item = self._normalize_entry(item)
        if normalized_item is None:
            raise ValueError('Invalid credential payload')

        if not normalized_item.get('secret_value'):
            raise ValueError('secret value is required')

        machine_id = normalized_item.get('machine_id') or self.SERVER_MACHINE_ID
        with self._lock:
            items = self._read_payload(machine_id)
            self._ensure_unique_name(items, normalized_item.get('name') or '')
            items.append(normalized_item)
            self._write_payload(machine_id, items)
        return dict(normalized_item)

    def update_item(self, cred_id: str, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError('payload is required')

        with self._lock:
            old_machine_id, old_item, old_items = self._find_item_unlocked(cred_id)
            if old_item is None:
                raise FileNotFoundError('Credential not found')

            now_text = self._now_text()
            merged = dict(old_item)
            merged.update(payload)
            merged['cred_id'] = old_item.get('cred_id')
            merged['created_at'] = old_item.get('created_at') or now_text
            merged['updated_at'] = now_text

            if 'secret_value' not in payload and 'password' not in payload and 'value' not in payload:
                merged['secret_value'] = old_item.get('secret_value') or ''

            normalized_item = self._normalize_entry(merged, default_machine_id=old_machine_id)
            if normalized_item is None:
                raise ValueError('Invalid credential payload')
            if not normalized_item.get('secret_value'):
                raise ValueError('secret value is required')

            new_machine_id = normalized_item.get('machine_id') or self.SERVER_MACHINE_ID
            if self._normalize_machine_id(old_machine_id) == self._normalize_machine_id(new_machine_id):
                self._ensure_unique_name(old_items, normalized_item.get('name') or '', skip_cred_id=cred_id)
                updated_items = []
                for item in old_items:
                    if item.get('cred_id') == cred_id:
                        updated_items.append(normalized_item)
                    else:
                        updated_items.append(item)
                self._write_payload(new_machine_id, updated_items)
            else:
                new_items = self._read_payload(new_machine_id)
                self._ensure_unique_name(new_items, normalized_item.get('name') or '')
                old_items = [item for item in old_items if item.get('cred_id') != cred_id]
                new_items.append(normalized_item)
                self._write_payload(old_machine_id, old_items)
                self._write_payload(new_machine_id, new_items)

        return dict(normalized_item)

    def delete_item(self, cred_id: str) -> dict:
        with self._lock:
            machine_id, item, items = self._find_item_unlocked(cred_id)
            if item is None:
                raise FileNotFoundError('Credential not found')

            kept_items = [current for current in items if current.get('cred_id') != cred_id]
            self._write_payload(machine_id, kept_items)
        return dict(item)
