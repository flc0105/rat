import json
import os
import tempfile
import threading
import uuid
from datetime import datetime

from core.utils.logger import logger


class DeviceGroupStore:
    """
    Device group persistence.

    Rules:
    - Groups are user-defined and have stable IDs.
    - Membership is keyed by machine_id, never by client_id / connection.
    - Deleting a group keeps machines but clears their group assignment.
    - Data is persisted under runtime as one small JSON document.
    """

    VERSION = 1

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        self._lock = threading.RLock()

    def _now_iso(self) -> str:
        return datetime.now().isoformat()

    def _normalize_group_id(self, value) -> str:
        return str(value or '').strip()

    def _normalize_machine_id(self, value) -> str:
        return str(value or '').strip().lower()

    def _normalize_group_name(self, value) -> str:
        return str(value or '').strip()

    def _empty_state(self) -> dict:
        return {
            'version': self.VERSION,
            'groups': [],
            'machine_groups': {},
        }

    def _read_unlocked(self) -> dict:
        if not os.path.isfile(self.file_path):
            return self._empty_state()

        try:
            with open(self.file_path, 'r', encoding='utf-8') as fp:
                raw = json.load(fp)
        except Exception:
            logger.error('DeviceGroupStore read failed: %s', self.file_path, exc_info=True)
            return self._empty_state()

        if not isinstance(raw, dict):
            return self._empty_state()

        groups = []
        seen_ids = set()
        seen_names = set()

        for item in raw.get('groups') or []:
            if not isinstance(item, dict):
                continue

            group_id = self._normalize_group_id(item.get('group_id') or item.get('id'))
            name = self._normalize_group_name(item.get('name'))
            if not group_id or not name:
                continue

            name_key = name.casefold()
            if group_id in seen_ids or name_key in seen_names:
                continue

            seen_ids.add(group_id)
            seen_names.add(name_key)
            groups.append({
                'group_id': group_id,
                'name': name,
                'created_at': str(item.get('created_at') or ''),
                'updated_at': str(item.get('updated_at') or ''),
            })

        valid_group_ids = {item['group_id'] for item in groups}
        machine_groups = {}
        raw_machine_groups = raw.get('machine_groups') or {}
        if isinstance(raw_machine_groups, dict):
            for machine_id, group_id in raw_machine_groups.items():
                machine_key = self._normalize_machine_id(machine_id)
                normalized_group_id = self._normalize_group_id(group_id)
                if machine_key and normalized_group_id in valid_group_ids:
                    machine_groups[machine_key] = normalized_group_id

        return {
            'version': self.VERSION,
            'groups': groups,
            'machine_groups': machine_groups,
        }

    def _write_unlocked(self, state: dict):
        dir_name = os.path.dirname(self.file_path)
        fd, temp_path = tempfile.mkstemp(
            prefix='device_groups_',
            suffix='.tmp',
            dir=dir_name,
        )

        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as fp:
                json.dump(state, fp, ensure_ascii=False, indent=2)
            os.replace(temp_path, self.file_path)
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                logger.warning('DeviceGroupStore temp cleanup failed: %s', temp_path, exc_info=True)

    def _copy_state(self, state: dict) -> dict:
        return {
            'groups': [dict(item) for item in state.get('groups') or []],
            'machine_groups': dict(state.get('machine_groups') or {}),
        }

    def _find_group_unlocked(self, state: dict, group_id: str):
        target = self._normalize_group_id(group_id)
        for item in state.get('groups') or []:
            if item.get('group_id') == target:
                return item
        return None

    def _assert_unique_name_unlocked(self, state: dict, name: str, exclude_group_id: str = ''):
        target_name = self._normalize_group_name(name)
        if not target_name:
            raise ValueError('Group name is required')
        if len(target_name) > 80:
            raise ValueError('Group name must be 80 characters or fewer')

        exclude_id = self._normalize_group_id(exclude_group_id)
        target_key = target_name.casefold()
        for item in state.get('groups') or []:
            if exclude_id and item.get('group_id') == exclude_id:
                continue
            if self._normalize_group_name(item.get('name')).casefold() == target_key:
                raise ValueError('A group with this name already exists')

        return target_name

    def get_state(self) -> dict:
        with self._lock:
            return self._copy_state(self._read_unlocked())

    def create_group(self, name: str) -> dict:
        with self._lock:
            state = self._read_unlocked()
            normalized_name = self._assert_unique_name_unlocked(state, name)
            now = self._now_iso()
            state['groups'].append({
                'group_id': uuid.uuid4().hex,
                'name': normalized_name,
                'created_at': now,
                'updated_at': now,
            })
            self._write_unlocked(state)
            return self._copy_state(state)

    def rename_group(self, group_id: str, name: str) -> dict:
        with self._lock:
            state = self._read_unlocked()
            group = self._find_group_unlocked(state, group_id)
            if group is None:
                raise ValueError('Device group not found')

            normalized_name = self._assert_unique_name_unlocked(
                state,
                name,
                exclude_group_id=group.get('group_id') or '',
            )
            group['name'] = normalized_name
            group['updated_at'] = self._now_iso()
            self._write_unlocked(state)
            return self._copy_state(state)

    def delete_group(self, group_id: str) -> dict:
        with self._lock:
            state = self._read_unlocked()
            target = self._normalize_group_id(group_id)
            if not target or self._find_group_unlocked(state, target) is None:
                raise ValueError('Device group not found')

            state['groups'] = [
                item
                for item in state.get('groups') or []
                if item.get('group_id') != target
            ]
            state['machine_groups'] = {
                machine_id: assigned_group_id
                for machine_id, assigned_group_id in (state.get('machine_groups') or {}).items()
                if assigned_group_id != target
            }
            self._write_unlocked(state)
            return self._copy_state(state)

    def assign_machine(self, machine_id: str, group_id: str = '') -> dict:
        machine_key = self._normalize_machine_id(machine_id)
        if not machine_key:
            raise ValueError('Invalid machine id')

        with self._lock:
            state = self._read_unlocked()
            target_group_id = self._normalize_group_id(group_id)

            if target_group_id:
                if self._find_group_unlocked(state, target_group_id) is None:
                    raise ValueError('Device group not found')
                state['machine_groups'][machine_key] = target_group_id
            else:
                state['machine_groups'].pop(machine_key, None)

            self._write_unlocked(state)
            return self._copy_state(state)
