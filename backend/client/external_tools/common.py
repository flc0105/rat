import json
import os
import platform
import re
import shlex

from core.platform.platform_identity import detect_platform_alias


_INSTANCE_PATTERN = re.compile(r'[^A-Za-z0-9_.-]+')


class ExternalToolCommon:
    """Common helpers shared by client-side external tool modules."""

    DOWNLOAD_TIMEOUT = (15, 600)
    DOWNLOAD_CHUNK_SIZE = 64 * 1024
    DEFAULT_STOP_TIMEOUT_SEC = 5
    DEFAULT_LOG_TAIL_BYTES = 65536

    @property
    def client_api(self):
        return self.command_host.client_api

    def _ensure_not_interrupted(self):
        return self.command_host._ensure_not_interrupted()

    def normalize_platform(self, value) -> str:
        text = str(value or '').strip().lower()
        aliases = {
            'windows': 'win',
            'win32': 'win',
            'darwin': 'mac',
            'macos': 'mac',
            'osx': 'mac',
            'linux': 'linux',
            'ios': 'ios',
            'common': '*',
            'all': '*',
            '*': '*',
        }
        return aliases.get(text, text)

    def normalize_arch(self, value) -> str:
        text = str(value or '').strip().lower().replace('-', '_')
        aliases = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'i386': '386',
            'i686': '386',
            'aarch64': 'arm64',
            'arm64': 'arm64',
        }
        return aliases.get(text, text)

    def local_target(self) -> tuple[str, str]:
        local_platform = self.normalize_platform(detect_platform_alias())
        local_arch = self.normalize_arch(platform.machine())
        if not local_platform or not local_arch:
            raise ValueError(f'unable to detect local platform/arch, got {local_platform or "unknown"}/{local_arch or "unknown"}')
        return local_platform, local_arch

    def validate_package_payload(self, payload: dict, action: str = '') -> tuple[str, str]:
        requested_platform = self.normalize_platform(payload.get('platform'))
        requested_arch = self.normalize_arch(payload.get('arch'))
        package_key = str(payload.get('package_key') or '').strip()
        package_id = str(payload.get('package_id') or payload.get('tool_id') or '').strip()

        if not package_id:
            raise ValueError('external tool payload.package_id is required')
        if not package_key:
            raise ValueError(f'external tool payload.package_key is required for {package_id}')
        if not requested_platform or not requested_arch:
            raise ValueError(f'external tool payload platform/arch is required for {package_id}, got {requested_platform or "unknown"}/{requested_arch or "unknown"}')

        local_platform, local_arch = self.local_target()
        platform_ok = requested_platform in ('*', local_platform)
        arch_ok = requested_arch in ('*', 'all', local_arch)
        if not platform_ok or not arch_ok:
            suffix = f' during {action}' if action else ''
            raise ValueError(
                f'external tool target mismatch{suffix}: payload requests '
                f'{requested_platform}/{requested_arch} ({package_key}) but this client is {local_platform}/{local_arch}'
            )
        return requested_platform, requested_arch

    def expand_path(self, path: str) -> str:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(str(path or '').strip())))

    def sanitize_instance_id(self, value) -> str:
        text = str(value or '').strip()
        text = _INSTANCE_PATTERN.sub('-', text).strip('.-_')
        return (text or 'default')[:96]

    def render_path_list(self, values):
        if isinstance(values, str):
            return shlex.split(values)
        if isinstance(values, list):
            return [str(item) for item in values]
        return []

    def is_url_like(self, value: str) -> bool:
        text = str(value or '').strip().lower()
        if '://' not in text:
            return False
        scheme = text.split('://', 1)[0]
        return bool(scheme) and all(ch.isalnum() or ch in '+-.' for ch in scheme)

    def should_expand_argv_item(self, value: str, index: int) -> bool:
        text = str(value or '').strip()
        if not text:
            return False
        if self.is_url_like(text):
            return False
        if index == 0:
            return True
        return (
            text.startswith('~')
            or text.startswith('/')
            or text.startswith('./')
            or text.startswith('../')
            or text.startswith('.\\')
            or text.startswith('..\\')
            or ('\\' in text)
        )

    def chmod(self, path: str):
        if not path or os.name == 'nt' or not os.path.exists(path):
            return
        mode = os.stat(path).st_mode
        os.chmod(path, mode | 0o111)

    def build_command_map(self, exec_paths: dict) -> dict:
        commands = {}
        for name, path in (exec_paths or {}).items():
            text = str(path or '').strip()
            if not text:
                continue
            commands[str(name)] = shlex.quote(self.expand_path(text))
        return commands

    def path_has_content(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        if os.path.isfile(path):
            return True
        if os.path.isdir(path):
            try:
                return any(os.scandir(path))
            except OSError:
                return False
        return True

    def read_json(self, path: str) -> dict:
        try:
            with open(path, 'r', encoding='utf-8') as file_obj:
                data = json.load(file_obj)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def write_json(self, path: str, data: dict):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as file_obj:
            json.dump(data, file_obj, ensure_ascii=False, indent=2)

    def runtime_parts_from_payload(self, payload: dict) -> tuple[str, str, str]:
        tool_id = str(payload.get('tool_id') or '').strip()
        package_id = str(payload.get('package_id') or '').strip()
        module_id = str(payload.get('module_id') or '').strip()
        if (not package_id or not module_id) and '.' in tool_id:
            package_id, module_id = tool_id.split('.', 1)
        if not package_id:
            package_id = tool_id
        return tool_id, package_id, module_id
