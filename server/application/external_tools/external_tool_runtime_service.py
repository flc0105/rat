import base64
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import zipfile
from datetime import datetime
from string import Template
from typing import Any

from core.platform.platform_identity import detect_platform_alias


_VAR_PATTERN = re.compile(r'{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}')


class ExternalToolRuntimeService:
    """
    Install and run external tools on server side, and build client-side run payloads.
    """

    def __init__(self, catalog_service, command_execution_api, install_root_dir: str, runtime_root_dir: str):
        self.catalog_service = catalog_service
        self.command_execution_api = command_execution_api
        self.install_root_dir = os.path.abspath(install_root_dir)
        self.runtime_root_dir = os.path.abspath(runtime_root_dir)
        os.makedirs(self.install_root_dir, exist_ok=True)
        os.makedirs(self.runtime_root_dir, exist_ok=True)

    def _normalize_arch(self, value: str = '') -> str:
        text = str(value or platform.machine() or '').strip().lower().replace('-', '_')
        aliases = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'i386': '386',
            'i686': '386',
            'aarch64': 'arm64',
            'arm64': 'arm64',
        }
        return aliases.get(text, text)

    def _render_value(self, value: Any, context: dict) -> Any:
        if isinstance(value, str):
            def replace(match):
                key = match.group(1)
                return str(context.get(key, match.group(0)))
            return _VAR_PATTERN.sub(replace, value)
        if isinstance(value, list):
            return [self._render_value(item, context) for item in value]
        if isinstance(value, dict):
            return {key: self._render_value(val, context) for key, val in value.items()}
        return value

    def _expand_path(self, path: str) -> str:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(str(path or '').strip())))

    def _coerce_param_value(self, spec: dict, value: Any) -> Any:
        param_type = str(spec.get('type') or 'string').strip().lower()
        if value is None or value == '':
            if spec.get('default') is not None:
                value = spec.get('default')
            elif spec.get('required'):
                raise ValueError(f'param {spec.get("name")} is required')
            else:
                return ''
        if param_type in ('int', 'integer', 'number'):
            try:
                return int(value)
            except Exception:
                raise ValueError(f'param {spec.get("name")} must be an integer')
        if param_type in ('bool', 'boolean'):
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in ('1', 'true', 'yes', 'on')
        return str(value)

    def resolve_params(self, meta: dict, params: dict | None) -> dict:
        source = params if isinstance(params, dict) else {}
        resolved = {}
        for spec in meta.get('params') or []:
            name = str(spec.get('name') or '').strip()
            if not name:
                continue
            resolved[name] = self._coerce_param_value(spec, source.get(name))
        for key, value in source.items():
            if key not in resolved:
                resolved[key] = value
        return resolved

    def _base_context(self, meta: dict, params: dict, *, install_root: str, runtime_root: str) -> dict:
        version = str(meta.get('version') or 'default').strip() or 'default'
        context = {
            'id': str(meta.get('id') or '').strip(),
            'name': str(meta.get('name') or meta.get('id') or '').strip(),
            'display_name': str(meta.get('display_name') or meta.get('id') or '').strip(),
            'version': version,
            'side': str(meta.get('side') or '').strip(),
            'platform': detect_platform_alias(),
            'arch': self._normalize_arch(),
            'external_tools_root': install_root,
            'external_tools_runtime': runtime_root,
            'runtime_dir': runtime_root,
        }
        context.update(params or {})
        install_template = str((meta.get('install') or {}).get('install_dir') or '{{external_tools_root}}/{{id}}/{{version}}')
        install_dir = self._render_value(install_template, context)
        context['install_dir'] = install_dir
        return context

    def build_server_context(self, meta: dict, params: dict) -> dict:
        context = self._base_context(
            meta,
            params,
            install_root=self.install_root_dir,
            runtime_root=self.runtime_root_dir,
        )
        for key in ('external_tools_root', 'external_tools_runtime', 'runtime_dir', 'install_dir'):
            context[key] = self._expand_path(context[key])
        return context

    def build_client_context(self, meta: dict, params: dict) -> dict:
        context = self._base_context(
            meta,
            params,
            install_root='~/.ops/external_tools/installed',
            runtime_root='~/.ops/external_tools/runtime',
        )
        return context

    def _assert_tool_usable(self, meta: dict, side: str, platform_alias: str = ''):
        expected_side = str(meta.get('side') or '').strip().lower()
        if expected_side and expected_side != side:
            raise ValueError(f'{meta.get("id")} is a {expected_side} tool, not {side}')
        target_platform = platform_alias or detect_platform_alias()
        if target_platform == '*':
            return
        platforms = meta.get('platforms') or []
        if platforms and '*' not in platforms and target_platform not in platforms:
            raise ValueError(f'{meta.get("id")} does not support platform {target_platform}')

    def _safe_extract_zip(self, zip_path: str, destination_dir: str) -> str:
        destination_dir = self._expand_path(destination_dir)
        os.makedirs(destination_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as archive:
            for member in archive.infolist():
                member_path = os.path.abspath(os.path.join(destination_dir, member.filename))
                if os.path.commonpath([destination_dir, member_path]) != destination_dir:
                    raise ValueError(f'Unsafe zip entry detected: {member.filename}')
            archive.extractall(destination_dir)
        return destination_dir

    def _chmod_executable(self, path: str):
        if not path or os.name == 'nt' or not os.path.exists(path):
            return
        current_mode = os.stat(path).st_mode
        os.chmod(path, current_mode | 0o111)

    def _resolve_skip_path(self, meta: dict, context: dict) -> str:
        install = meta.get('install') or {}
        skip_template = str(install.get('skip_if_exists') or '').strip()
        if not skip_template:
            executable_rel_path = str((meta.get('package') or {}).get('executable_rel_path') or '').strip()
            if executable_rel_path:
                skip_template = '{{install_dir}}/' + executable_rel_path
            else:
                skip_template = '{{install_dir}}'
        return self._expand_path(self._render_value(skip_template, context))

    def _install_package_if_needed(self, meta: dict, context: dict) -> dict:
        install_dir = self._expand_path(self._render_value('{{install_dir}}', context))
        context['install_dir'] = install_dir
        skip_path = self._resolve_skip_path(meta, context)
        installed = os.path.exists(skip_path)
        extracted = False

        if not installed:
            package = meta.get('package') or {}
            filename = str(package.get('filename') or '').strip()
            if not filename:
                raise ValueError('package.filename is required')
            package_path = self.catalog_service.get_package_path(filename)
            os.makedirs(install_dir, exist_ok=True)
            self._safe_extract_zip(package_path, install_dir)
            extracted = True

        executable_rel_path = str((meta.get('package') or {}).get('executable_rel_path') or '').strip()
        executable_path = self._expand_path(os.path.join(install_dir, executable_rel_path)) if executable_rel_path else skip_path
        self._chmod_executable(executable_path)

        return {
            'install_dir': install_dir,
            'skip_path': skip_path,
            'already_installed': installed,
            'extracted': extracted,
            'executable_path': executable_path,
        }

    def _write_config(self, meta: dict, context: dict) -> dict:
        config = meta.get('config') or {}
        target_template = str(config.get('target') or '').strip()
        template = config.get('template')
        if not target_template or template is None:
            return {}

        target = self._expand_path(self._render_value(target_template, context))
        content = self._render_value(str(template), context)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'w', encoding='utf-8') as file_obj:
            file_obj.write(content)
        return {'target': target, 'size': os.path.getsize(target)}

    def _build_runtime_spec(self, meta: dict, context: dict) -> dict:
        runtime = self._render_value(meta.get('runtime') or {}, context)
        argv = runtime.get('argv') or []
        if isinstance(argv, str):
            argv = shlex.split(argv)
        if not isinstance(argv, list) or not argv:
            raise ValueError('runtime.argv is required')
        argv = [self._expand_path(str(item)) if index == 0 or '/' in str(item) or '\\' in str(item) else str(item) for index, item in enumerate(argv)]

        cwd = self._expand_path(runtime.get('cwd') or context.get('install_dir') or '.')
        stdout = self._expand_path(runtime.get('stdout') or os.path.join(self.runtime_root_dir, meta.get('id') or 'tool', 'stdout.log'))
        stderr = runtime.get('stderr') or 'stdout'
        if stderr != 'stdout':
            stderr = self._expand_path(stderr)
        pid_file = self._expand_path(runtime.get('pid_file') or os.path.join(self.runtime_root_dir, meta.get('id') or 'tool', 'tool.pid'))
        return {
            'argv': argv,
            'cwd': cwd,
            'stdout': stdout,
            'stderr': stderr,
            'pid_file': pid_file,
        }

    def _start_detached_process(self, runtime_spec: dict) -> subprocess.Popen:
        os.makedirs(runtime_spec['cwd'], exist_ok=True)
        os.makedirs(os.path.dirname(runtime_spec['stdout']), exist_ok=True)
        os.makedirs(os.path.dirname(runtime_spec['pid_file']), exist_ok=True)
        stdout_file = open(runtime_spec['stdout'], 'ab')
        if runtime_spec.get('stderr') == 'stdout':
            stderr_target = subprocess.STDOUT
            stderr_file = None
        else:
            os.makedirs(os.path.dirname(runtime_spec['stderr']), exist_ok=True)
            stderr_file = open(runtime_spec['stderr'], 'ab')
            stderr_target = stderr_file

        popen_kwargs = {
            'cwd': runtime_spec['cwd'],
            'stdin': subprocess.DEVNULL,
            'stdout': stdout_file,
            'stderr': stderr_target,
            'close_fds': True,
            'shell': False,
        }
        try:
            if os.name == 'nt':
                flags = 0
                flags |= getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
                flags |= getattr(subprocess, 'DETACHED_PROCESS', 0)
                process = subprocess.Popen(runtime_spec['argv'], creationflags=flags, **popen_kwargs)
            else:
                process = subprocess.Popen(runtime_spec['argv'], start_new_session=True, **popen_kwargs)
        finally:
            stdout_file.close()
            if stderr_file is not None:
                stderr_file.close()
        with open(runtime_spec['pid_file'], 'w', encoding='utf-8') as file_obj:
            file_obj.write(str(process.pid))
        return process

    def _write_state_file(self, meta: dict, runtime_spec: dict, process: subprocess.Popen, install_info: dict) -> str:
        state_dir = os.path.dirname(runtime_spec['pid_file'])
        os.makedirs(state_dir, exist_ok=True)
        state_file = os.path.join(state_dir, 'state.json')
        payload = {
            'tool_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or '',
            'version': meta.get('version') or '',
            'side': meta.get('side') or '',
            'pid': process.pid,
            'argv': runtime_spec.get('argv') or [],
            'cwd': runtime_spec.get('cwd') or '',
            'stdout': runtime_spec.get('stdout') or '',
            'stderr': runtime_spec.get('stderr') or '',
            'pid_file': runtime_spec.get('pid_file') or '',
            'install_dir': install_info.get('install_dir') or '',
            'started_at': datetime.now().isoformat(timespec='seconds'),
        }
        with open(state_file, 'w', encoding='utf-8') as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False, indent=2)
        return state_file

    def install_and_run_server(self, tool_id: str, params: dict | None = None) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')
        resolved_params = self.resolve_params(meta, params)
        context = self.build_server_context(meta, resolved_params)
        install_info = self._install_package_if_needed(meta, context)
        config_info = self._write_config(meta, context)
        runtime_spec = self._build_runtime_spec(meta, context)
        process = self._start_detached_process(runtime_spec)
        state_file = self._write_state_file(meta, runtime_spec, process, install_info)
        return {
            'tool_id': meta.get('id') or '',
            'side': 'server',
            'pid': process.pid,
            'install': install_info,
            'config': config_info,
            'runtime': runtime_spec,
            'state_file': state_file,
            'message': f'{meta.get("display_name") or meta.get("id")} started on server',
        }

    def _encode_payload_arg(self, payload: dict) -> str:
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'__json__:{encoded}'

    def build_client_payload(self, meta: dict, params: dict | None = None) -> dict:
        resolved_params = self.resolve_params(meta, params)
        context = self.build_client_context(meta, resolved_params)
        rendered_meta = self._render_value(meta, context)
        package = rendered_meta.get('package') or {}
        filename = str(package.get('filename') or '').strip()
        if not filename:
            raise ValueError('package.filename is required')
        download_url = str(package.get('download_url') or '').strip()
        if not download_url:
            download_url = f'/api/external-tools/packages/{filename}'

        install = rendered_meta.get('install') or {}
        config = rendered_meta.get('config') or {}
        runtime = rendered_meta.get('runtime') or {}
        skip_if_exists = str(install.get('skip_if_exists') or '').strip()
        if not skip_if_exists:
            executable_rel_path = str(package.get('executable_rel_path') or '').strip()
            skip_if_exists = '{{install_dir}}/' + executable_rel_path if executable_rel_path else '{{install_dir}}'
            skip_if_exists = self._render_value(skip_if_exists, context)

        config_payload = {}
        if config.get('target') and config.get('template') is not None:
            config_payload = {
                'target': config.get('target'),
                'content': self._render_value(str(config.get('template')), context),
            }

        return {
            'tool_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or meta.get('id') or '',
            'version': meta.get('version') or '',
            'side': 'client',
            'package': {
                'filename': filename,
                'download_url': download_url,
                'executable_rel_path': package.get('executable_rel_path') or '',
            },
            'install': {
                'install_dir': context.get('install_dir') or '',
                'skip_if_exists': skip_if_exists,
            },
            'config': config_payload,
            'runtime': runtime,
        }

    def install_and_run_client(self, client_id: str, tool_id: str, params: dict | None = None, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')
        payload = self.build_client_payload(meta, params)
        command = f'external_tool_run {self._encode_payload_arg(payload)}'
        return self.command_execution_api.submit_web_command(client_id, command, tab_id=tab_id)
