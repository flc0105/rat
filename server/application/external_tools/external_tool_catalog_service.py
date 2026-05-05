import glob
import json
import os
from copy import deepcopy
from typing import Any

from core.platform.platform_identity import detect_platform_alias


class ExternalToolCatalogService:
    """
    External tool meta catalog.

    First-version convention:
    - one meta file describes one executable resource
    - frps and frpc should be maintained as separate meta files
    - packages are maintained by the server under packages_root_dir
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

    def _normalize_platforms(self, meta: dict) -> list[str]:
        source = meta.get('platforms')
        if source is None:
            source = meta.get('platform')
        if isinstance(source, str):
            items = [source]
        elif isinstance(source, list):
            items = source
        else:
            items = []
        normalized = []
        seen = set()
        for item in items:
            value = self._normalize_platform(item)
            if not value or value in seen:
                continue
            seen.add(value)
            normalized.append(value)
        return normalized or ['*']

    def _normalize_side_value(self, value: Any) -> str:
        text = str(value or '').strip().lower()
        if text in ('server', 'client'):
            return text
        return ''

    def _normalize_sides(self, value: Any) -> list[str]:
        if isinstance(value, list):
            source = value
        elif isinstance(value, tuple):
            source = list(value)
        else:
            source = [value]

        sides = []
        seen = set()
        for item in source:
            side = self._normalize_side_value(item)
            if not side or side in seen:
                continue
            seen.add(side)
            sides.append(side)

        return sides or ['client']


    #xt
    def _normalize_cli_aliases(self, value: Any) -> list[str]:
        if isinstance(value, str):
            source = [value]
        elif isinstance(value, list):
            source = value
        elif isinstance(value, tuple):
            source = list(value)
        else:
            source = []

        aliases = []
        seen = set()
        for item in source:
            alias = str(item or '').strip()
            if not alias or alias in seen:
                continue
            seen.add(alias)
            aliases.append(alias)
        return aliases

    def _normalize_cli(self, meta: dict) -> dict:
        source = meta.get('cli') if isinstance(meta.get('cli'), dict) else {}
        enabled = bool(source.get('enabled'))
        aliases = self._normalize_cli_aliases(source.get('aliases') or source.get('alias'))

        cli = dict(source)
        cli['enabled'] = enabled and bool(aliases)
        cli['aliases'] = aliases
        cli['arg_mode'] = str(source.get('arg_mode') or 'raw_append').strip() or 'raw_append'
        return cli

    def _platform_matches(self, meta: dict, platform_alias: str = '') -> bool:
        target = self._normalize_platform(platform_alias or '')
        if not target:
            return True
        platforms = meta.get('platforms') or []
        return not platforms or '*' in platforms or target in platforms

    def _arch_matches(self, meta: dict, arch: str = '') -> bool:
        target = str(arch or '').strip().lower()
        expected = str(meta.get('arch') or '').strip().lower()
        return not target or not expected or expected in ('*', 'all') or expected == target

    def _side_matches(self, meta: dict, side: str = '') -> bool:
        target = self._normalize_side_value(side or '')
        if not target:
            return True
        return target in (meta.get('sides') or [])

    # end xt


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

    def normalize_meta(self, meta: dict, path: str = '') -> dict:
        item = deepcopy(meta)
        tool_id = str(item.get('id') or item.get('name') or '').strip()
        if not tool_id:
            if path:
                tool_id = os.path.splitext(os.path.basename(path))[0]
            else:
                raise ValueError('external tool id is required')
        item['id'] = tool_id
        item['name'] = str(item.get('name') or tool_id).strip() or tool_id
        item['display_name'] = str(item.get('display_name') or item.get('name') or tool_id).strip() or tool_id
        item['description'] = str(item.get('description') or '').strip()
        item['version'] = str(item.get('version') or '').strip()
        sides = self._normalize_sides(item.get('side'))
        item['sides'] = sides
        item['side'] = sides[0] if len(sides) == 1 else sides
        item['platforms'] = self._normalize_platforms(item)
        item['arch'] = str(item.get('arch') or item.get('architecture') or '').strip().lower()
        item['category'] = str(item.get('category') or '').strip()
        item['tags'] = item.get('tags') if isinstance(item.get('tags'), list) else []
        item['params'] = [p for p in (self._normalize_param(p) for p in (item.get('params') or [])) if p]

        item['cli'] = self._normalize_cli(item)

        package = item.get('package') if isinstance(item.get('package'), dict) else {}
        filename = str(package.get('filename') or item.get('filename') or '').strip()
        if filename:
            package['filename'] = os.path.basename(filename)
        package['download_url'] = str(package.get('download_url') or item.get('download_url') or '').strip()
        package['executable_rel_path'] = str(package.get('executable_rel_path') or item.get('executable_rel_path') or '').strip()
        item['package'] = package

        install = item.get('install') if isinstance(item.get('install'), dict) else {}
        item['install'] = install

        config = item.get('config') if isinstance(item.get('config'), dict) else {}
        item['config'] = config

        runtime = item.get('runtime') if isinstance(item.get('runtime'), dict) else {}
        item['runtime'] = runtime

        if path:
            item['_meta_path'] = os.path.abspath(path)
        return item

    def list_tools(self) -> list[dict]:
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
                    'side': '',
                    'sides': [],
                    'platforms': [],
                    'params': [],
                    'error': str(e),
                    '_meta_path': os.path.abspath(path),
                })
        return items

    # def get_catalog(self) -> dict:
    #     return {'items': self.list_tools()}

    def get_catalog(self) -> dict:
        return {
            'items': self.list_tools(),
            'server_platform': detect_platform_alias(),
        }

    def get_tool(self, tool_id: str) -> dict:
        target = str(tool_id or '').strip()
        if not target:
            raise ValueError('tool_id is required')
        for item in self.list_tools():
            if str(item.get('id') or '').strip() == target:
                if item.get('error'):
                    raise ValueError(item.get('error'))
                return item
        raise FileNotFoundError(f'External tool not found: {tool_id}')

    def get_meta_path(self, tool_id: str) -> str:
        meta = self.get_tool(tool_id)
        path = os.path.abspath(str(meta.get('_meta_path') or '').strip())
        if not path:
            raise FileNotFoundError(f'External tool meta not found: {tool_id}')
        if os.path.commonpath([self.metas_root_dir, path]) != self.metas_root_dir:
            raise ValueError('invalid external tool meta path')
        if not os.path.isfile(path):
            raise FileNotFoundError(f'External tool meta not found: {tool_id}')
        return path

    def read_meta_content(self, tool_id: str) -> dict:
        path = self.get_meta_path(tool_id)
        with open(path, 'r', encoding='utf-8') as file_obj:
            content = file_obj.read()
        return {
            'tool_id': tool_id,
            'path': path,
            'name': os.path.basename(path),
            'content': content,
            'size': len(content.encode('utf-8')),
        }

    def save_meta_content(self, tool_id: str, content: str) -> dict:
        path = self.get_meta_path(tool_id)
        text = str(content or '')
        try:
            parsed = json.loads(text)
        except Exception as e:
            raise ValueError(f'Invalid JSON meta: {e}')
        if not isinstance(parsed, dict):
            raise ValueError('Invalid JSON meta: expected object')

        normalized = self.normalize_meta(parsed, path=path)
        new_tool_id = str(normalized.get('id') or '').strip()
        if new_tool_id and new_tool_id != str(tool_id or '').strip():
            raise ValueError('Changing external tool id is not supported from this editor')

        with open(path, 'w', encoding='utf-8') as file_obj:
            file_obj.write(text)
        return {
            'tool_id': tool_id,
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

    #xt
    def list_cli_aliases(self, side: str = '', platform_alias: str = '', arch: str = '') -> list[dict]:
        items = []
        for meta in self.list_tools():
            if meta.get('error'):
                continue
            cli = meta.get('cli') if isinstance(meta.get('cli'), dict) else {}
            if not cli.get('enabled'):
                continue
            if not self._side_matches(meta, side):
                continue
            if not self._platform_matches(meta, platform_alias):
                continue
            if not self._arch_matches(meta, arch):
                continue

            for alias in cli.get('aliases') or []:
                items.append({
                    'alias': alias,
                    'tool_id': meta.get('id') or '',
                    'display_name': meta.get('display_name') or meta.get('id') or '',
                    'description': meta.get('description') or '',
                    'side': side or (meta.get('sides') or ['client'])[0],
                    'platforms': meta.get('platforms') or [],
                    'arch': meta.get('arch') or '',
                    'package': meta.get('package') or {},
                    'cli': cli,
                    'meta': meta,
                })

        return sorted(items, key=lambda item: (item.get('alias') or '').lower())

    def resolve_cli_alias(self, alias: str, side: str = '', platform_alias: str = '', arch: str = '') -> dict:
        target = str(alias or '').strip()
        if not target:
            raise ValueError('external tool cli alias is required')

        matches = [
            item for item in self.list_cli_aliases(side=side, platform_alias=platform_alias, arch=arch)
            if item.get('alias') == target
        ]

        if not matches:
            raise FileNotFoundError(f'External tool CLI alias not found: {target}')

        if len(matches) > 1:
            lines = [f'Ambiguous external tool CLI alias: {target}', '', 'Matched:']
            for item in matches:
                lines.append(f'- {item.get("alias")} -> {item.get("tool_id")}')
            lines.append('Please keep cli.aliases unique for the current side/platform/arch.')
            raise ValueError('\n'.join(lines))

        return matches[0]
