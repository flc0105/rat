from client.commands.common.providers.process.ps_provider import (
    PsutilProcessProvider,
)
from core.utils.command_output import (
    StructuredCommandResult,
    render_structured_result,
)


class PsService:
    """
    acmd ps service.

    输出字段：
    - pid
    - ppid
    - owner
    - arch
    - executable

    筛选：
    - acmd ps 1234
    - acmd ps --pid 1234
    - acmd ps --name python
    """

    def __init__(self, owner=None):
        self.owner = owner

    def build_acmd_ps_result(self, args_dict):
        pid = args_dict.get('pid')
        name = args_dict.get('name')
        output_json = bool(args_dict.get('json', False))

        rows = self.collect_ps_rows(pid=pid, name=name)

        result = StructuredCommandResult(
            status=1,
            data=rows,
            shape='table',
        )

        return render_structured_result(
            result,
            output_format='json' if output_json else 'text',
        )

    def collect_ps_rows(self, pid=None, name=''):
        if pid is not None:
            pid = int(pid)

            if pid < 0:
                raise ValueError('PID must not be negative: {}'.format(pid))

        name = str(name or '').strip()

        rows = PsutilProcessProvider().collect()

        if pid is not None:
            rows = [
                row for row in rows
                if row.get('pid') == pid
            ]

        if name:
            rows = [
                row for row in rows
                if self._row_matches_name(row, name)
            ]

        rows = self._clean_and_sort_rows(rows)

        if not rows:
            if pid is not None:
                raise RuntimeError(
                    'No process found for pid {}'.format(pid)
                )

            if name:
                raise RuntimeError(
                    'No process found for name {}'.format(name)
                )

            raise RuntimeError('No processes found')

        return rows

    def _row_matches_name(self, row, name):
        needle = str(name or '').strip().lower()

        if not needle:
            return True

        candidates = [
            row.get('_name') or '',
            row.get('executable') or '',
            row.get('_exe_path') or '',
        ]

        for candidate in candidates:
            text = str(candidate or '').lower()

            if needle in text:
                return True

        return False

    def _clean_and_sort_rows(self, rows):
        result = []

        for row in rows or []:
            result.append({
                'pid': self._normalize_int_or_empty(row.get('pid')),
                'ppid': self._normalize_int_or_empty(row.get('ppid')),
                'owner': row.get('owner') or '',
                'arch': row.get('arch') or '',
                'executable': row.get('executable') or '',
            })

        result.sort(key=lambda item: self._pid_sort_key(item.get('pid')))
        return result

    def _normalize_int_or_empty(self, value):
        if value in (None, ''):
            return ''

        try:
            return int(value)
        except Exception:
            return ''

    def _pid_sort_key(self, value):
        try:
            return int(value)
        except Exception:
            return 0