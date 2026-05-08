import glob
import json
import logging
import os
import platform
from copy import deepcopy
from typing import Any

from core.platform.platform_identity import detect_platform_alias


logger = logging.getLogger(__name__)


class ExternalToolCatalogService:
    """
    External tool package catalog.

    v2 convention:
    - one meta file describes one installable package
    - package may expose multiple daemon modules under modules[]
    - package may expose multiple CLI execs under execs{}
    - platform/arch selection is resolved from platform_packages{}
    - side is no longer a capability constraint; target host decides platform/arch
    """

    def __init__(self, metas_root_dir: str, packages_root_dir: str):
        self.metas_root_dir = os.path.abspath(metas_root_dir)
        self.packages_root_dir = os.path.abspath(packages_root_dir)
        os.makedirs(self.metas_root_dir, exist_ok=True)
        os.makedirs(self.packages_root_dir, exist_ok=True)

    def _read_json_file(self, path: str) -> dict:
        with open(path, 'r', encoding='utf-8') as file_obj:
            data = json.load(file_obj)
        if not isinstance(data, dict):
            raise ValueError(f'Invalid external tool meta: {path}')
        return data

    def _normalize_platform(self, value: Any) -> str:
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

    def _normalize_arch(self, value: Any) -> str:
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

    def _platform_key(self, platform_alias: str, arch: str) -> str:
        platform_value = self._normalize_platform(platform_alias)
        arch_value = self._normalize_arch(arch)
        if not platform_value or not arch_value:
            return ''
        return f'{platform_value}-{arch_value}'

    def _normalize_param(self, item: Any) -> dict:
        if not isinstance(item, dict):
            return {}
        name = str(item.get('name') or '').strip()
        if not name:
            return {}
        param = dict(item)
        param['name'] = name
        param['type'] = str(item.get('type') or 'string').strip().lower() or 'string'
        param['required'] = bool(item.get('required'))
        param['description'] = str(item.get('description') or '').strip()
        return param

    def _normalize_params(self, values: Any) -> list[dict]:
        source = values if isinstance(values, list) else []
        return [p for p in (self._normalize_param(p) for p in source) if p]

    def _normalize_platform_package(self, key: str, item: Any) -> dict:
        if not isinstance(item, dict):
            item = {}
        package = dict(item)
        raw_key = str(package.get('key') or key or '').strip().lower().replace('_', '-')
        if not raw_key:
            platform_value = self._normalize_platform(package.get('platform'))
            arch_value = self._normalize_arch(package.get('arch'))
            raw_key = self._platform_key(platform_value, arch_value)
        if not raw_key:
            raise ValueError('platform package key is required')

        if '-' in raw_key:
            maybe_platform, maybe_arch = raw_key.split('-', 1)
        else:
            maybe_platform, maybe_arch = '', ''

        platform_value = self._normalize_platform(package.get('platform') or maybe_platform)
        arch_value = self._normalize_arch(package.get('arch') or maybe_arch)
        if not platform_value or not arch_value:
            raise ValueError(f'platform package {raw_key} requires platform and arch')

        filename = str(package.get('filename') or '').strip()
        if filename:
            package['filename'] = os.path.basename(filename)

        package['key'] = raw_key
        package['platform'] = platform_value
        package['arch'] = arch_value
        package['download_url'] = str(package.get('download_url') or '').strip()
        package['root'] = str(package.get('root') or '').strip()
        return package

    def _normalize_platform_packages(self, meta: dict) -> dict[str, dict]:
        raw = meta.get('platform_packages')
        if raw is None:
            raw = meta.get('packages')
        if not isinstance(raw, dict) or not raw:
            raise ValueError('platform_packages is required')

        packages = {}
        for key, value in raw.items():
            package = self._normalize_platform_package(str(key), value)
            packages[package['key']] = package
        return packages

    def _normalize_execs(self, meta: dict, platform_packages: dict[str, dict]) -> dict[str, dict]:
        raw = meta.get('execs')
        if not isinstance(raw, dict) or not raw:
            raise ValueError('execs is required')

        execs = {}
        for name, value in raw.items():
            exec_name = str(name or '').strip()
            if not exec_name:
                continue
            source = value if isinstance(value, dict) else {}
            paths = source.get('paths') if isinstance(source.get('paths'), dict) else {}
            normalized_paths = {}
            for key, path in paths.items():
                package_key = str(key or '').strip().lower().replace('_', '-')
                if package_key in platform_packages and str(path or '').strip():
                    normalized_paths[package_key] = str(path or '').strip()
            if not normalized_paths:
                raise ValueError(f'exec {exec_name} requires paths for platform packages')
            item = dict(source)
            item['name'] = exec_name
            item['paths'] = normalized_paths
            item['description'] = str(item.get('description') or '').strip()
            item['enabled'] = bool(item.get('enabled', True))
            item['arg_mode'] = str(item.get('arg_mode') or 'raw_append').strip() or 'raw_append'
            execs[exec_name] = item
        if not execs:
            raise ValueError('execs is required')
        return execs

    def _normalize_module(self, package: dict, item: Any) -> dict:
        if not isinstance(item, dict):
            return {}
        module_id = str(item.get('id') or item.get('name') or '').strip()
        if not module_id:
            return {}
        module = deepcopy(item)
        package_id = package.get('id') or ''
        tool_id = f'{package_id}.{module_id}'
        module['id'] = module_id
        module['tool_id'] = tool_id
        module['package_id'] = package_id
        module['name'] = str(module.get('name') or module_id).strip() or module_id
        module['display_name'] = str(module.get('display_name') or module.get('name') or module_id).strip() or module_id
        module['description'] = str(module.get('description') or package.get('description') or '').strip()
        module['version'] = str(module.get('version') or package.get('version') or '').strip()
        module['category'] = str(module.get('category') or package.get('category') or '').strip()
        module['tags'] = module.get('tags') if isinstance(module.get('tags'), list) else list(package.get('tags') or [])
        module['execution'] = str(module.get('execution') or module.get('mode') or 'daemon').strip().lower() or 'daemon'
        if module['execution'] != 'daemon':
            raise ValueError(f'module {module_id} execution must be daemon')
        module['exec'] = str(module.get('exec') or module.get('exec_name') or module_id).strip()
        if module['exec'] not in (package.get('execs') or {}):
            raise ValueError(f'module {module_id} references unknown exec: {module["exec"]}')

        common_params = self._normalize_params(package.get('params'))
        module_params = self._normalize_params(module.get('params'))
        module['params'] = common_params + module_params
        module['config'] = module.get('config') if isinstance(module.get('config'), dict) else {}
        module['runtime'] = module.get('runtime') if isinstance(module.get('runtime'), dict) else {}
        if isinstance(module.get('runtimes'), list):
            module['runtimes'] = module.get('runtimes')
        elif isinstance(module.get('runtime_variants'), list):
            module['runtimes'] = module.get('runtime_variants')
        else:
            module['runtimes'] = []
        module['lifecycle'] = module.get('lifecycle') if isinstance(module.get('lifecycle'), dict) else (package.get('lifecycle') if isinstance(package.get('lifecycle'), dict) else {})
        module['web'] = module.get('web') if isinstance(module.get('web'), dict) else (package.get('web') if isinstance(package.get('web'), dict) else {})
        module['package_display_name'] = package.get('display_name') or package_id
        return module

    def _derive_package_platforms(self, platform_packages: dict[str, dict]) -> list[str]:
        result = []
        seen = set()
        for item in platform_packages.values():
            value = self._normalize_platform(item.get('platform'))
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result or ['*']

    def _derive_package_arches(self, platform_packages: dict[str, dict]) -> list[str]:
        result = []
        seen = set()
        for item in platform_packages.values():
            value = self._normalize_arch(item.get('arch'))
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result or ['*']

    def normalize_meta(self, meta: dict, path: str = '') -> dict:
        item = deepcopy(meta)
        package_id = str(item.get('id') or item.get('name') or '').strip()
        if not package_id:
            if path:
                package_id = os.path.splitext(os.path.basename(path))[0]
            else:
                raise ValueError('external tool package id is required')

        item['id'] = package_id
        item['name'] = str(item.get('name') or package_id).strip() or package_id
        item['display_name'] = str(item.get('display_name') or item.get('name') or package_id).strip() or package_id
        item['description'] = str(item.get('description') or '').strip()
        item['version'] = str(item.get('version') or '').strip()
        item['category'] = str(item.get('category') or '').strip()
        item['tags'] = item.get('tags') if isinstance(item.get('tags'), list) else []
        item['params'] = self._normalize_params(item.get('params'))

        platform_packages = self._normalize_platform_packages(item)
        item['platform_packages'] = platform_packages
        item['package_keys'] = sorted(platform_packages.keys())
        item['platforms'] = self._derive_package_platforms(platform_packages)
        item['arches'] = self._derive_package_arches(platform_packages)
        item['arch'] = ','.join(item['arches']) if len(item['arches']) > 1 else (item['arches'][0] if item['arches'] else '')
        item['execs'] = self._normalize_execs(item, platform_packages)

        install = item.get('install') if isinstance(item.get('install'), dict) else {}
        item['install'] = install
        item['config'] = item.get('config') if isinstance(item.get('config'), dict) else {}
        item['runtime'] = item.get('runtime') if isinstance(item.get('runtime'), dict) else {}
        item['lifecycle'] = item.get('lifecycle') if isinstance(item.get('lifecycle'), dict) else {}

        modules = []
        for module_item in (item.get('modules') if isinstance(item.get('modules'), list) else []):
            module = self._normalize_module(item, module_item)
            if module:
                modules.append(module)
        if not modules:
            raise ValueError('modules is required')
        item['modules'] = modules

        # Side is intentionally no longer a constraint, but expose both values so old UI labels/status chips remain harmless.
        item['sides'] = ['server', 'client']
        item['side'] = ['server', 'client']

        if path:
            item['_meta_path'] = os.path.abspath(path)
        return item

    def list_packages(self) -> list[dict]:
        items = []
        pattern = os.path.join(self.metas_root_dir, '**/*.json')
        for path in sorted(glob.iglob(pattern, recursive=True)):
            if not os.path.isfile(path):
                continue
            try:
                items.append(self.normalize_meta(self._read_json_file(path), path=path))
            except Exception as e:
                items.append({
                    'id': os.path.splitext(os.path.basename(path))[0],
                    'display_name': os.path.basename(path),
                    'description': f'Invalid meta: {e}',
                    'platforms': [],
                    'arches': [],
                    'modules': [],
                    'execs': {},
                    'error': str(e),
                    '_meta_path': os.path.abspath(path),
                })
        return items

    def list_tools(self) -> list[dict]:
        """Return runnable module records."""
        modules = []
        for package in self.list_packages():
            if package.get('error'):
                continue
            for module in package.get('modules') or []:
                row = deepcopy(module)
                row['package'] = self.public_package_ref(package)
                row['package_meta'] = package
                modules.append(row)
        return modules

    def get_catalog(self) -> dict:
        return {
            'items': self.list_packages(),
            'modules': self.list_tools(),
            'server_platform': detect_platform_alias(),
            'server_arch': self._normalize_arch(platform.machine()),
        }

    def get_package(self, package_id: str) -> dict:
        target = str(package_id or '').strip()
        if not target:
            raise ValueError('package_id is required')
        for item in self.list_packages():
            if str(item.get('id') or '').strip() == target:
                if item.get('error'):
                    raise ValueError(item.get('error'))
                return item
        raise FileNotFoundError(f'External tool package not found: {package_id}')

    def get_tool(self, tool_id: str) -> dict:
        target = str(tool_id or '').strip()
        if not target:
            raise ValueError('tool_id is required')
        for item in self.list_tools():
            if str(item.get('tool_id') or item.get('id') or '').strip() == target:
                return item
        raise FileNotFoundError(f'External tool module not found: {tool_id}')

    def get_module(self, tool_id: str) -> dict:
        return self.get_tool(tool_id)

    def public_package_ref(self, package: dict) -> dict:
        return {
            'id': package.get('id') or '',
            'name': package.get('name') or package.get('id') or '',
            'display_name': package.get('display_name') or package.get('id') or '',
            'version': package.get('version') or '',
            'platforms': package.get('platforms') or [],
            'arches': package.get('arches') or [],
            'package_keys': package.get('package_keys') or [],
        }

    def select_package_key(self, package: dict, platform_alias: str = '', arch: str = '') -> str:
        packages = package.get('platform_packages') if isinstance(package.get('platform_packages'), dict) else {}
        package_id = package.get('id') or 'package'

        if not packages:
            logger.warning(
                '[external-tools] package has no platform packages: package_id=%s',
                package_id,
            )
            raise ValueError(f'{package_id} has no platform packages')

        target_platform = self._normalize_platform(platform_alias or '')
        target_arch = self._normalize_arch(arch or '')
        exact_key = self._platform_key(target_platform, target_arch)

        if exact_key and exact_key in packages:
            logger.info(
                '[external-tools] selected exact package build: package_id=%s target=%s/%s package_key=%s supported=%s',
                package_id,
                target_platform or 'unknown',
                target_arch or 'unknown',
                exact_key,
                sorted(packages.keys()),
            )
            return exact_key

        matches = []
        for key, item in packages.items():
            platform_ok = not target_platform or item.get('platform') == '*' or item.get('platform') == target_platform
            arch_ok = not target_arch or item.get('arch') in ('*', 'all') or item.get('arch') == target_arch
            if platform_ok and arch_ok:
                matches.append(key)

        if len(matches) == 1:
            logger.info(
                '[external-tools] selected compatible package build: package_id=%s target=%s/%s package_key=%s supported=%s',
                package_id,
                target_platform or 'unknown',
                target_arch or 'unknown',
                matches[0],
                sorted(packages.keys()),
            )
            return matches[0]

        if matches:
            logger.warning(
                '[external-tools] ambiguous package build: package_id=%s target=%s/%s matches=%s supported=%s',
                package_id,
                target_platform or 'unknown',
                target_arch or 'unknown',
                matches,
                sorted(packages.keys()),
            )
            raise ValueError(f'Ambiguous platform package for {package_id}: {target_platform}/{target_arch} -> {", ".join(matches)}')

        logger.warning(
            '[external-tools] unsupported package target: package_id=%s target=%s/%s supported=%s raw_platform=%s raw_arch=%s',
            package_id,
            target_platform or 'unknown',
            target_arch or 'unknown',
            sorted(packages.keys()),
            platform_alias or '',
            arch or '',
        )

        raise ValueError(f'{package_id} does not support {target_platform or "unknown"}/{target_arch or "unknown"}')

    def resolve_exec_rel_path(self, package: dict, exec_name: str, package_key: str) -> str:
        execs = package.get('execs') if isinstance(package.get('execs'), dict) else {}
        exec_item = execs.get(str(exec_name or '').strip())
        if not isinstance(exec_item, dict):
            raise ValueError(f'exec not found: {exec_name}')
        paths = exec_item.get('paths') if isinstance(exec_item.get('paths'), dict) else {}
        rel_path = str(paths.get(package_key) or '').strip()
        if not rel_path:
            raise ValueError(f'exec {exec_name} does not support {package_key}')
        return rel_path

    def get_meta_path(self, package_id: str) -> str:
        meta = self.get_package(package_id)
        path = os.path.abspath(str(meta.get('_meta_path') or '').strip())
        if not path:
            raise FileNotFoundError(f'External tool meta not found: {package_id}')
        if os.path.commonpath([self.metas_root_dir, path]) != self.metas_root_dir:
            raise ValueError('invalid external tool meta path')
        if not os.path.isfile(path):
            raise FileNotFoundError(f'External tool meta not found: {package_id}')
        return path

    def read_meta_content(self, package_id: str) -> dict:
        path = self.get_meta_path(package_id)
        with open(path, 'r', encoding='utf-8') as file_obj:
            content = file_obj.read()
        return {
            'tool_id': package_id,
            'package_id': package_id,
            'path': path,
            'name': os.path.basename(path),
            'content': content,
            'size': len(content.encode('utf-8')),
        }

    def save_meta_content(self, package_id: str, content: str) -> dict:
        path = self.get_meta_path(package_id)
        text = str(content or '')
        try:
            parsed = json.loads(text)
        except Exception as e:
            raise ValueError(f'Invalid JSON meta: {e}')
        if not isinstance(parsed, dict):
            raise ValueError('Invalid JSON meta: expected object')

        normalized = self.normalize_meta(parsed, path=path)
        new_package_id = str(normalized.get('id') or '').strip()
        if new_package_id and new_package_id != str(package_id or '').strip():
            raise ValueError('Changing external tool package id is not supported from this editor')

        with open(path, 'w', encoding='utf-8') as file_obj:
            file_obj.write(text)
        return {
            'tool_id': package_id,
            'package_id': package_id,
            'path': path,
            'name': os.path.basename(path),
            'size': len(text.encode('utf-8')),
        }

    def get_package_path(self, filename: str) -> str:
        safe_name = os.path.basename(str(filename or '').strip())
        if not safe_name:
            raise ValueError('filename is required')
        path = os.path.abspath(os.path.join(self.packages_root_dir, safe_name))
        if os.path.commonpath([self.packages_root_dir, path]) != self.packages_root_dir:
            raise ValueError('invalid package filename')
        if not os.path.isfile(path):
            raise FileNotFoundError(f'External tool package not found: {safe_name}')
        return path

    def get_package_download_filename(self, package_id: str, platform_alias: str = '', arch: str = '') -> str:
        package = self.get_package(package_id)
        key = self.select_package_key(package, platform_alias=platform_alias, arch=arch)
        info = (package.get('platform_packages') or {}).get(key) or {}
        filename = str(info.get('filename') or '').strip()
        if not filename:
            raise ValueError(f'package {package_id} has no filename for {key}')
        return filename

    def _platform_matches(self, package: dict, platform_alias: str = '') -> bool:
        target = self._normalize_platform(platform_alias or '')
        if not target:
            return True
        platforms = package.get('platforms') or []
        return not platforms or '*' in platforms or target in platforms

    def _arch_matches(self, package: dict, arch: str = '') -> bool:
        target = self._normalize_arch(arch or '')
        if not target:
            return True
        return any((item.get('arch') in ('*', 'all') or item.get('arch') == target) for item in (package.get('platform_packages') or {}).values())

    def list_cli_aliases(self, side: str = '', platform_alias: str = '', arch: str = '') -> list[dict]:
        del side
        items = []
        for package in self.list_packages():
            if package.get('error'):
                continue
            if not self._platform_matches(package, platform_alias):
                continue
            if not self._arch_matches(package, arch):
                continue
            try:
                package_key = self.select_package_key(package, platform_alias=platform_alias, arch=arch)
            except Exception:
                continue
            for exec_name, exec_item in (package.get('execs') or {}).items():
                if not isinstance(exec_item, dict) or not exec_item.get('enabled', True):
                    continue
                rel_path = str((exec_item.get('paths') or {}).get(package_key) or '').strip()
                if not rel_path:
                    continue
                items.append({
                    'alias': exec_name,
                    'exec_name': exec_name,
                    'tool_id': package.get('id') or '',
                    'package_id': package.get('id') or '',
                    'display_name': package.get('display_name') or package.get('id') or '',
                    'description': exec_item.get('description') or package.get('description') or '',
                    'side': 'client',
                    'platforms': package.get('platforms') or [],
                    'arch': package.get('arch') or '',
                    'package_key': package_key,
                    'executable_rel_path': rel_path,
                    'package': package,
                    'exec': exec_item,
                    'cli': {
                        'enabled': True,
                        'exec_name': exec_name,
                        'arg_mode': exec_item.get('arg_mode') or 'raw_append',
                        'cwd': exec_item.get('cwd') or '',
                        'timeout_sec': exec_item.get('timeout_sec'),
                    },
                    'meta': package,
                })
        return sorted(items, key=lambda item: (item.get('alias') or '').lower())

    def resolve_cli_alias(self, alias: str, side: str = '', platform_alias: str = '', arch: str = '') -> dict:
        target = str(alias or '').strip()
        if not target:
            raise ValueError('external tool exec name is required')

        matches = [
            item for item in self.list_cli_aliases(side=side, platform_alias=platform_alias, arch=arch)
            if item.get('alias') == target
        ]

        if not matches:
            raise FileNotFoundError(f'External tool exec not found: {target}')

        if len(matches) > 1:
            lines = [f'Ambiguous external tool exec: {target}', '', 'Matched:']
            for item in matches:
                lines.append(f'- {item.get("alias")} -> {item.get("package_id")}')
            lines.append('Keep exec names unique for the current platform/arch.')
            raise ValueError('\n'.join(lines))

        return matches[0]
