import json
import os
import re
import shlex
import time
from datetime import datetime
from typing import Any

from core.external_tools.archive import safe_extract_zip_archive
from core.external_tools.paths import build_command_map, chmod_executable, path_has_content
from core.external_tools.payload import primary_exec_name
from server.application.external_tools.external_tool_runtime_component import ExternalToolRuntimeComponent


class ExternalToolInstallSupport(ExternalToolRuntimeComponent):
    """Install-status, package extraction, config and runtime-spec helpers."""

    def _install_manifest_path(self, install_dir: str) -> str:
        return os.path.join(self._expand_path(install_dir), '.external_tool_package.json')
    def _local_package_file_info(self, package: dict, context: dict) -> dict:
        try:
            package_file = self._package_file(package, context.get('package_key') or '')
            filename = str(package_file.get('filename') or '').strip()
            package_path = self.catalog_service.get_package_path(filename) if filename else ''
        except Exception as e:
            return {
                'cache_dir': '',
                'cache_path': '',
                'cached': False,
                'exists': False,
                'size': 0,
                'mtime': '',
                'error': str(e),
            }
        exists = bool(package_path and os.path.isfile(package_path))
        info = {
            'cache_dir': os.path.dirname(package_path) if package_path else '',
            'cache_path': package_path,
            'cached': exists,
            'exists': exists,
            'size': 0,
            'mtime': '',
        }
        if exists:
            try:
                stat = os.stat(package_path)
                info['size'] = int(stat.st_size)
                info['mtime'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
            except OSError as e:
                info['error'] = str(e)
        return info
    def _write_install_manifest(self, package: dict, context: dict, exec_paths: dict):
        install_dir = self._expand_path(context.get('install_dir') or '')
        if not install_dir:
            return
        data = {
            'schema_version': 1,
            'package_id': package.get('id') or '',
            'version': package.get('version') or '',
            'platform': context.get('platform') or '',
            'arch': context.get('arch') or '',
            'package_key': context.get('package_key') or '',
            'package_root': context.get('package_root') or '',
            'exec_paths': exec_paths or {},
            'installed_at': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        }
        os.makedirs(install_dir, exist_ok=True)
        with open(self._install_manifest_path(install_dir), 'w', encoding='utf-8') as file_obj:
            json.dump(data, file_obj, ensure_ascii=False, indent=2)
    def _safe_extract_zip(self, zip_path: str, destination_dir: str) -> str:
        return safe_extract_zip_archive(zip_path, destination_dir, self._expand_path)
    def _chmod_executable(self, path: str):
        chmod_executable(path)
    def _primary_exec_name(self, package: dict, module: dict | None = None) -> str:
        return primary_exec_name(package, module)
    def _default_package_skip_template(self, package: dict, context: dict) -> str:
        del package, context
        # Package-first install state should be tied to the package extraction
        # directory, not to one runnable executable. Multi-exec packages such as
        # frp can expose frps/frpc from the same installation, and using the first
        # exec as the package marker makes status fragile. Module start still
        # validates the concrete executable through runtime.argv.
        return '{{install_dir}}'
    def _path_has_content(self, path: str) -> bool:
        return path_has_content(path)
    def _install_log_path(self, install_dir: str) -> str:
        return os.path.join(self._expand_path(install_dir), '.install.log')
    def _read_install_log(self, install_dir: str) -> str:
        path = self._install_log_path(install_dir)
        if not os.path.isfile(path):
            return ''
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                return fh.read()
        except OSError:
            return ''
    def _write_install_log(self, install_dir: str, lines) -> str:
        content = '\n'.join(str(line) for line in (lines or []) if str(line or '').strip())
        if not content:
            return ''
        try:
            os.makedirs(self._expand_path(install_dir), exist_ok=True)
            with open(self._install_log_path(install_dir), 'w', encoding='utf-8') as fh:
                fh.write(content)
                fh.write('\n')
        except OSError:
            pass
        return content
    def _build_command_map(self, exec_paths: dict) -> dict:
        return build_command_map(exec_paths, self._expand_path)
    def _client_skip_path(self, package: dict, context: dict, module: dict | None = None) -> str:
        del module
        install = package.get('install') if isinstance(package.get('install'), dict) else {}
        package_file = self._package_file(package, context.get('package_key') or '')
        skip_template = str(package_file.get('skip_if_exists') or install.get('skip_if_exists') or '').strip()
        if not skip_template:
            skip_template = self._default_package_skip_template(package, context)
        return self._render_value(skip_template, context)
    def _resolve_skip_path(self, package: dict, context: dict, module: dict | None = None) -> str:
        del module
        install = package.get('install') if isinstance(package.get('install'), dict) else {}
        package_file = self._package_file(package, context.get('package_key') or '')
        skip_template = str(package_file.get('skip_if_exists') or install.get('skip_if_exists') or '').strip()
        if not skip_template:
            skip_template = self._default_package_skip_template(package, context)
        return self._expand_path(self._render_value(skip_template, context))
    def _build_install_status(self, package: dict, context: dict, module: dict | None = None) -> dict:
        install_dir = self._expand_path(self._render_value('{{install_dir}}', context))
        context['install_dir'] = install_dir
        rel_execs, abs_bins = self._resolved_exec_context(package, context.get('package_key') or '', install_dir)
        context['exec'] = rel_execs
        context['bin'] = abs_bins
        skip_path = self._resolve_skip_path(package, context, module=module)
        exec_name = self._primary_exec_name(package, module)
        executable_path = abs_bins.get(exec_name) or skip_path

        # Installation state is deliberately FS-driven and strict. Do not infer
        # installed from meta, previous state, frontend cache, or a loose marker.
        # A package is installed only when its install_dir still exists and every
        # declared exec for the selected package build exists at the deterministic
        # path declared by meta. If the install dir is manually deleted, this must
        # immediately become False on the next status read.
        install_dir_exists = os.path.isdir(install_dir)
        missing_execs = self._missing_exec_paths(abs_bins) if install_dir_exists else dict(abs_bins)
        installed = install_dir_exists and not missing_execs

        package_cache = self._local_package_file_info(package, context)
        commands = self._build_command_map(abs_bins)

        return {
            'tool_id': module.get('tool_id') if module else package.get('id') or '',
            'package_id': package.get('id') or '',
            'module_id': module.get('id') if module else '',
            'display_name': package.get('display_name') or package.get('id') or '',
            'source': self._package_source(package, context.get('package_key') or ''),
            'side': context.get('side') or '',
            'platform': context.get('platform') or '',
            'arch': context.get('arch') or '',
            'package_key': context.get('package_key') or '',
            'installed': installed,
            'install_dir': install_dir,
            'install_dir_exists': install_dir_exists,
            'skip_path': skip_path,
            'exec_name': exec_name,
            'executable_path': self._expand_path(executable_path) if executable_path else '',
            'exec_paths': abs_bins,
            'missing_execs': missing_execs,
            'cache': package_cache,
            'cached': bool(package_cache.get('cached')),
            'cache_path': package_cache.get('cache_path') or '',
            'command': shlex.quote(self._expand_path(executable_path)) if executable_path else '',
            'commands': commands,
            'install_log': self._read_install_log(install_dir),
            'install_log_path': self._install_log_path(install_dir),
        }
    def _install_package_if_needed(self, package: dict, context: dict) -> dict:
        status = self._build_install_status(package, context)
        install_dir = status['install_dir']
        already_installed = bool(status['installed'])
        extracted = False
        package_file = self._package_file(package, context.get('package_key') or '')
        filename = str(package_file.get('filename') or '').strip()
        if not filename:
            raise ValueError('platform package filename is required')
        package_path = self.catalog_service.get_package_path(filename)
        install_log = [
            f'Package: {package.get("display_name") or package.get("id") or "external tool"}',
            f'Target: server {context.get("platform") or ""} {context.get("arch") or ""}'.rstrip(),
            f'Platform package key: {context.get("package_key") or "-"}',
            f'Install dir: {install_dir}',
            f'Package source: local package file',
            f'Package file: {package_path}',
        ]
        if not already_installed:
            os.makedirs(install_dir, exist_ok=True)
            install_log.append(f'Extracting package to: {install_dir}')
            self._safe_extract_zip(package_path, install_dir)
            extracted = True
        else:
            install_log.append('Existing installation is valid; extraction skipped.')

        # Re-read status after extraction instead of blindly reporting success; this
        # keeps the UI honest if a package filename/root/marker is misconfigured.
        status = self._build_install_status(package, context)
        if not status.get('installed'):
            missing = status.get('missing_execs') or {}
            install_log.append(f'Validation failed; missing execs: {missing or "-"}')
            self._write_install_log(install_dir, install_log)
            if missing:
                raise FileNotFoundError(f'Package was extracted but configured executable paths were not found: {missing}')
            raise FileNotFoundError(f'Package was extracted but install directory was not found: {status.get("install_dir") or install_dir}')
        for name, path in (status.get('exec_paths') or {}).items():
            self._chmod_executable(path)
            install_log.append(f'Validated exec {name}: {path}')
        self._write_install_manifest(package, context, context.get('exec') or {})
        persisted_install_log = self._write_install_log(install_dir, install_log)
        status.update({
            'installed': True,
            'already_installed': already_installed,
            'extracted': extracted,
            'filename': filename,
            'package': package_path,
            'package_source': 'local',
            'used_cache': False,
            'downloaded': False,
            'install_log': persisted_install_log,
            'message': 'already installed' if already_installed else 'installed successfully',
        })
        return status
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
        runtime_source = self._module_runtime_for_platform(meta, context.get('platform') or '', context.get('arch') or '')
        runtime = self._render_value(runtime_source or {}, context)
        argv = runtime.get('argv') or []
        if isinstance(argv, str):
            argv = shlex.split(argv)
        if not isinstance(argv, list) or not argv:
            raise ValueError('runtime.argv is required')
        argv = self._append_runtime_extra_args(argv, runtime, context)
        argv = [
            self._expand_path(str(item)) if self._should_expand_argv_item(str(item), index) else str(item)
            for index, item in enumerate(argv)
        ]
        if argv:
            executable = self._expand_path(argv[0])
            if not os.path.isfile(executable):
                raise FileNotFoundError(f'Configured executable not found: {executable}')
            argv[0] = executable
            self._chmod_executable(executable)
        cwd = self._expand_path(runtime.get('cwd') or context.get('install_dir') or '.')
        if not os.path.isdir(cwd):
            raise FileNotFoundError(f'Configured runtime cwd not found: {cwd}')
        stdout = self._expand_path(runtime.get('stdout') or os.path.join(context['instance_runtime_dir'], 'stdout.log'))
        stderr = runtime.get('stderr') or 'stdout'
        if stderr != 'stdout':
            stderr = self._expand_path(stderr)
        pid_file = self._expand_path(runtime.get('pid_file') or os.path.join(context['instance_runtime_dir'], 'tool.pid'))
        state_file = self._expand_path(runtime.get('state_file') or context.get('state_file') or os.path.join(os.path.dirname(pid_file), 'state.json'))
        return {
            'argv': argv,
            'cwd': cwd,
            'stdout': stdout,
            'stderr': stderr,
            'pid_file': pid_file,
            'state_file': state_file,
        }
