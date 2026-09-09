import threading
import uuid
from datetime import datetime


class DeviceGroupStore:
    """
    Device group persistence.

    Rules:
    - Groups are user-defined and have stable IDs.
    - Membership is keyed by machine_id, never by client_id / connection.
    - Deleting a group keeps machines but clears their group assignment.
    - Data is persisted in the shared runtime/rch.db database.
    """

    VERSION = 1

    def __init__(self, database):
        self.database = database
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
        conn = self.database.connection()
        groups = [
            {
                'group_id': row['group_id'],
                'name': row['name'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
            }
            for row in conn.execute(
                'SELECT group_id, name, created_at, updated_at FROM device_groups ORDER BY created_at ASC, group_id ASC'
            ).fetchall()
        ]
        machine_groups = {
            row['machine_id']: row['group_id']
            for row in conn.execute(
                'SELECT machine_id, group_id FROM device_group_members'
            ).fetchall()
        }
        return {
            'version': self.VERSION,
            'groups': groups,
            'machine_groups': machine_groups,
        }

    def _write_unlocked(self, state: dict):
        with self.database.transaction() as conn:
            conn.execute('DELETE FROM device_group_members')
            conn.execute('DELETE FROM device_groups')
            for item in state.get('groups') or []:
                conn.execute(
                    'INSERT INTO device_groups(group_id, name, created_at, updated_at) VALUES (?, ?, ?, ?)',
                    (
                        item.get('group_id') or '', item.get('name') or '',
                        item.get('created_at') or '', item.get('updated_at') or '',
                    ),
                )
            valid_group_ids = {str(item.get('group_id') or '') for item in state.get('groups') or []}
            for machine_id, group_id in (state.get('machine_groups') or {}).items():
                if str(group_id or '') not in valid_group_ids:
                    continue
                conn.execute(
                    'INSERT INTO device_group_members(machine_id, group_id) VALUES (?, ?)',
                    (self._normalize_machine_id(machine_id), str(group_id or '').strip()),
                )

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
