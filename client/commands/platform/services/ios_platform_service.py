import json
import os
import platform
import shutil
import sys
import time

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.platform.utils.ios_util import get_ios_username, _safe_call, get_ios_device_info, \
    get_ios_process_info, get_ios_bundle_info, get_ios_contacts
from client.config.config import UPLOAD_BASE_URL
from core.utils.client_util import get_executable_path, upload_file_via_http
from core.utils.command_output import StructuredCommandResult
from core.utils.logger import logger

upload_url = UPLOAD_BASE_URL.rstrip('/') + '/api/files/upload'


class iOSPlatformService:

    def __init__(self, owner):
        self.owner = owner

    def list_directory(self, path):
        try:
            target = os.path.expanduser((path or '.').strip())
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'

            entries = []
            for name in os.listdir(target):
                full = os.path.join(target, name)
                is_dir = os.path.isdir(full)
                is_link = os.path.islink(full)
                display_name = f'{name}/' if is_dir else (f'{name}@' if is_link else name)
                entries.append((0 if is_dir else 1, name.lower(), display_name))

            entries.sort(key=lambda x: (x[0], x[1]))

            return 1, '\n'.join(item[2] for item in entries)

        except Exception as e:
            return 0, f'ls failed: {e}'

    def get_username(self):
        try:
            return 1, str(get_ios_username())
        except Exception as e:
            return 0, f'whoami failed: {e}'

    def touch(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: touch <path>'

            parent = os.path.dirname(target)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)

            with open(target, 'a', encoding='utf-8'):
                os.utime(target, None)

            return 1, f'File touched: {target}'

        except Exception as e:
            return 0, f'touch failed: {e}'

    def mkdir(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: mkdir <path>'

            os.makedirs(target, exist_ok=True)
            return 1, f'Directory created: {target}'

        except Exception as e:
            return 0, f'mkdir failed: {e}'

    def rm(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: rm <file>'

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if os.path.isdir(target):
                return 0, f'Is a directory: {target}'

            os.remove(target)
            return 1, f'File removed: {target}'

        except Exception as e:
            return 0, f'rm failed: {e}'

    def rmdir(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: rmdir <dir>'

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'

            shutil.rmtree(target)
            return 1, f'Directory removed: {target}'

        except Exception as e:
            return 0, f'rmdir failed: {e}'

    def cat(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: cat <file>'

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isfile(target):
                return 0, f'Not a file: {target}'

            with open(target, 'r', encoding='utf-8', errors='replace') as f:
                return 1, f.read()

        except Exception as e:
            return 0, f'cat failed: {e}'

    def md5sum(self, path):
        try:
            import hashlib
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: md5sum <file>'
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isfile(target):
                return 0, f'Not a file: {target}'

            md5 = hashlib.md5()
            with open(target, 'rb') as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b''):
                    md5.update(chunk)

            return 1, f'{md5.hexdigest()}  {target}'
        except Exception as e:
            return 0, f'md5sum failed: {e}'

    def printenv(self, name):
        try:
            key = (name or '').strip()
            if key:
                return 1, str(os.environ.get(key, ''))

            lines = []
            for env_name in sorted(os.environ.keys()):
                lines.append(f'{env_name}={os.environ.get(env_name, "")}')
            return 1, '\n'.join(lines)
        except Exception as e:
            return 0, f'printenv failed: {e}'

    def echo(self, text):
        try:
            import re
            raw = str(text or '')

            def repl(match):
                name = match.group(1) or match.group(2) or ''
                return str(os.environ.get(name, ''))

            rendered = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([^}]+)\}', repl, raw)
            return 1, rendered
        except Exception as e:
            return 0, f'echo failed: {e}'

    def collect_info(self):
        try:
            from pathlib import Path
            import os
            device = get_ios_device_info()
            proc = get_ios_process_info()
            bundle = get_ios_bundle_info()

            info = {
                'device_name': device.get('device_name'),
                'device_model': device.get('device_model'),
                'device_type': device.get('device_type'),
                'machine_name': device.get('machine_name') or platform.machine(),
                'hostname': device.get('hostname'),
                'system': device.get('system'),
                'system_version': device.get('system_version'),
                'identifier_for_vendor': device.get('identifier_for_vendor'),
                'platform': _safe_call(platform.platform),
                'kernel_release': _safe_call(platform.release),
                'kernel_version': _safe_call(platform.version),
                'python_compiler': _safe_call(platform.python_compiler),
                'python_version': sys.version,
                'python_version_short': _safe_call(platform.python_version),
                'process_name': proc.get('process_name'),
                'process_id': proc.get('process_id'),
                'username': proc.get('username'),
                'executable_path': get_executable_path(),
                'processor_count': proc.get('processor_count'),
                'physical_memory': proc.get('physical_memory'),
                'system_boot_time': proc.get('system_boot_time'),
                'system_uptime': proc.get('system_uptime'),
                'os_version_string': proc.get('operating_system_version_string'),
                'low_power_mode_enabled': proc.get('low_power_mode_enabled'),
                'bundle_identifier': bundle.get('bundle_identifier'),
                'bundle_path': bundle.get('bundle_path'),
                'bundle_executable_path': bundle.get('executable_path') or sys.executable,
                'bundle_name': bundle.get('bundle_name'),
                'app_name': bundle.get('app_name'),
                'bundle_version': bundle.get('bundle_version'),
                'bundle_short_version': bundle.get('bundle_short_version'),
                'cwd': os.getcwd(),
                'home': os.path.expanduser('~') or str(Path.home()),
                'documents': os.path.expanduser('~/Documents'),
                'temp': os.path.abspath(os.getenv('TMPDIR', '/tmp'))
            }

            return StructuredCommandResult(
                status=1,
                data=info,
                shape='dict',
                width=24,
            )

        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to get system info: {e}'

    def read_clipboard(self):
        try:
            import clipboard
            return 1, clipboard.get() or ''
        except Exception as e:
            return 0, f'Failed to read clipboard: {e}'

    def write_clipboard(self, text):
        try:
            import clipboard
            clipboard.set(text or '')
            return 1, 'Clipboard updated'
        except Exception as e:
            return 0, f'Failed to write clipboard: {e}'

    def open_url(self, url):
        try:
            import webbrowser
            target = (url or '').strip()
            if not target:
                return 0, 'Usage: openurl <url>'
            ok = webbrowser.open(target)
            return 1, f'URL opened: {ok}'
        except Exception as e:
            return 0, f'Failed to open URL: {e}'

    def clear_console(self):
        try:
            import console
            console.clear()
            return 1, 'Console cleared'
        except Exception as e:
            return 0, f'Failed to clear console: {e}'

    def quick_look(self, path):
        try:
            import console

            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: quicklook <path>'
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'

            console.quicklook(target)
            return 1, f'Preview opened: {target}'
        except Exception as e:
            return 0, f'Failed to preview file: {e}'

    def open_in(self, path):
        try:
            import console

            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: openin <path>'
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'

            console.open_in(target)
            return 1, f'Open In launched: {target}'
        except Exception as e:
            return 0, f'Failed to open file externally: {e}'

    def get_location(self):
        try:
            import location

            location.start_updates()
            time.sleep(1.5)
            data = location.get_location()
            location.stop_updates()

            if not data:
                return 0, 'No location data'

            return 1, json.dumps(data, ensure_ascii=False)
        except CommandCancelledError:
            try:
                import location
                location.stop_updates()
            except Exception:
                pass
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            try:
                import location
                location.stop_updates()
            except Exception:
                pass
            return 0, 'Command timed out'
        except Exception as e:
            try:
                import location
                location.stop_updates()
            except Exception:
                pass
            return 0, f'Failed to get location: {e}'

    def speak(self, text):
        try:
            import speech
            speech.say(text or '')
            return 1, 'Speech started'
        except Exception as e:
            return 0, f'Failed to speak text: {e}'

    def list_contacts(self):
        try:
            result = get_ios_contacts()
            return StructuredCommandResult(
                status=1,
                data=result,
                shape='table',
            )
        except Exception as e:
            return 0, f'Failed to list contacts: {e}'

    def pick_upload(self, kind):
        try:
            import io
            import os
            import json
            import photos
            import dialogs

            kind = (kind or 'photo').strip().lower()

            if kind == 'photo':
                image = photos.pick_image()
                if image is None:
                    return 0, 'No photo selected'

                buf = io.BytesIO()
                if image.mode not in ('RGB', 'L'):
                    image = image.convert('RGB')
                image.save(buf, format='JPEG', quality=90)
                buf.seek(0)

                response = upload_file_via_http(
                    file_source=buf,
                    category='Pythonista',
                    upload_url=upload_url,
                    client_id=getattr(self.owner.socket, 'client_id', '') or '',
                    filename='photo.jpg',
                )

            elif kind == 'file':
                file_path = dialogs.pick_document()
                if not file_path:
                    return 0, 'No file selected'

                response = upload_file_via_http(
                    file_source=file_path,
                    category='Pythonista',
                    upload_url=upload_url,
                    filename=os.path.basename(file_path),
                    client_id=getattr(self.owner.socket, 'client_id', '') or '',
                )

            else:
                return 0, "kind must be 'photo' or 'file'"

            result = {
                'response_text': '',
                'status_code': response.status_code,
                'ok': response.ok,
            }

            try:
                result['response'] = response.json()
            except Exception:
                result['response_text'] = response.text

            return 1, json.dumps(result, ensure_ascii=False)

        except Exception as e:
            return 0, f'Failed to pick/upload: {e}'

    def acmd_alert(self, args_dict):
        try:
            title = args_dict.get('title', '')
            message = args_dict['message']
            import console
            button = console.alert(title or 'Alert', message or '', 'OK', hide_cancel_button=True)
            return 1, f'Alert closed: {button}'
        except Exception as e:
            return 0, f'Failed to show alert: {e}'

    def acmd_notify(self, args_dict):
        try:
            title = args_dict.get('title', '')
            message = args_dict['message']
            import notification
            notification.schedule(
                message or '',
                delay=0,
                sound_name=None,
                action_url=None,
                title=title or 'Notice'
            )
            return 1, 'Notification scheduled'
        except Exception as e:
            return 0, f'Failed to send notification: {e}'

    def acmd_find(self, args_dict):
        try:
            path = args_dict.get('path', '.')
            keyword = args_dict['keyword']

            target = os.path.expanduser((path or '.').strip())
            word = (keyword or '').strip()

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'
            if not word:
                return 0, 'Option "--keyword" cannot be empty'

            results = []
            for root, dirs, files in os.walk(target):
                for name in dirs + files:
                    if word.lower() in name.lower():
                        results.append(os.path.join(root, name))

            if not results:
                return 1, ''

            return 1, '\n'.join(results)
        except Exception as e:
            return 0, f'find failed: {e}'

    def acmd_tree(self, args_dict):
        try:
            path = args_dict.get('path', '.')
            max_depth = args_dict.get('max_depth', 3)

            target = os.path.expanduser((path or '.').strip())
            depth_limit = int(max_depth)

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'
            if depth_limit < 0:
                return 0, 'Option "--max_depth" must be >= 0'

            lines = [os.path.basename(target.rstrip('/')) or target]

            def walk(current, prefix='', depth=0):
                if depth >= depth_limit:
                    return

                items = sorted(
                    os.listdir(current),
                    key=lambda name: (
                        0 if os.path.isdir(os.path.join(current, name)) else 1,
                        name.lower()
                    )
                )

                for i, name in enumerate(items):
                    full = os.path.join(current, name)
                    is_last = i == len(items) - 1
                    branch = '└── ' if is_last else '├── '
                    suffix = '/' if os.path.isdir(full) else ''
                    lines.append(prefix + branch + name + suffix)

                    if os.path.isdir(full):
                        walk(full, prefix + ('    ' if is_last else '│   '), depth + 1)

            walk(target)
            return 1, '\n'.join(lines)
        except Exception as e:
            return 0, f'tree failed: {e}'

    def acmd_head(self, args_dict):
        try:
            path = os.path.expanduser((args_dict.get('path') or '').strip())
            lines_count = args_dict.get('lines', 10)
            lines_count = int(lines_count)

            if not os.path.exists(path):
                return 0, f'Path not found: {path}'
            if not os.path.isfile(path):
                return 0, f'Not a file: {path}'
            if lines_count < 0:
                return 0, 'Option "--lines" must be >= 0'

            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            return 1, ''.join(lines[:lines_count]).rstrip('\n')
        except Exception as e:
            return 0, f'head failed: {e}'

    def acmd_tail(self, args_dict):
        try:
            path = os.path.expanduser((args_dict.get('path') or '').strip())
            lines_count = args_dict.get('lines', 10)
            lines_count = int(lines_count)

            if not os.path.exists(path):
                return 0, f'Path not found: {path}'
            if not os.path.isfile(path):
                return 0, f'Not a file: {path}'
            if lines_count < 0:
                return 0, 'Option "--lines" must be >= 0'

            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            return 1, ''.join(lines[-lines_count:] if lines_count else []).rstrip('\n')
        except Exception as e:
            return 0, f'tail failed: {e}'

    def acmd_wget(self, args_dict):
        try:
            import urllib.request
            url = str(args_dict.get('url') or '').strip()
            out = str(args_dict.get('output') or '').strip()

            if not url:
                return 0, 'Missing required option: --url'

            if out:
                out_path = os.path.expanduser(out)
            else:
                name = url.rstrip('/').split('/')[-1] or 'download.bin'
                out_path = os.path.join(os.getcwd(), name)  # 默认下载到当前目录

            out_dir = os.path.dirname(out_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            with urllib.request.urlopen(url) as resp:
                with open(out_path, 'wb') as f:
                    while True:
                        chunk = resp.read(1024 * 256)
                        if not chunk:
                            break
                        f.write(chunk)

            return 1, out_path
        except Exception as e:
            return 0, f'wget failed: {e}'
