import json
import os
import sys

from client.bootstrap.client_app import Client
from client.config.config import SERVER_ADDR
from client.watchdog.watchdog_process import run_watchdog_worker_from_argv
from core.utils.logger import logger


def _pop_argv_value(flag_name: str) -> str:
    args = sys.argv[1:]
    for index, arg in enumerate(list(args)):
        if arg == flag_name and index + 1 < len(args):
            value = args[index + 1]
            del sys.argv[index + 1:index + 3]
            return str(value or '').strip()
        if arg.startswith(f'{flag_name}='):
            value = arg.split('=', 1)[1]
            del sys.argv[index + 1]
            return str(value or '').strip()
    return ''


def _write_update_ready_marker(file_path: str, client: Client):
    target_path = os.path.abspath(str(file_path or '').strip()) if file_path else ''
    if not target_path:
        return

    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    temp_path = f'{target_path}.tmp'
    payload = {
        'pid': os.getpid(),
        'client_id': client.client_id,
        'client_revision': str((client.info or {}).get('client_revision') or ''),
    }
    with open(temp_path, 'w', encoding='utf-8') as file_obj:
        json.dump(payload, file_obj)
    os.replace(temp_path, target_path)


def main():
    if '--watchdog-worker' in sys.argv[1:]:
        run_watchdog_worker_from_argv()
        sys.exit(0)

    update_ready_file = _pop_argv_value('--update-ready-file')

    client = Client(SERVER_ADDR)
    try:
        client.connect()
        _write_update_ready_marker(update_ready_file, client)
        client.wait()
    except KeyboardInterrupt:
        client.guard_manager.stop()
        sys.exit(0)
    except Exception as e:
        client.guard_manager.stop()
        logger.error(e, exc_info=True)


if __name__ == '__main__':
    main()

