import glob
import json
import os
from copy import deepcopy
from typing import Any


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

    def _normalize_side(self, value: Any) -> str:
        text = str(value or '').strip().lower()
        if text in ('server', 'client'):
            return text
        return text or 'client'

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
        item['side'] = self._normalize_side(item.get('side'))
        item['platforms'] = self._normalize_platforms(item)
        item['arch'] = str(item.get('arch') or item.get('architecture') or '').strip().lower()
        item['category'] = str(item.get('category') or '').strip()
        item['tags'] = item.get('tags') if isinstance(item.get('tags'), list) else []
        item['params'] = [p for p in (self._normalize_param(p) for p in (item.get('params') or [])) if p]

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
                    'platforms': [],
                    'params': [],
                    'error': str(e),
                    '_meta_path': os.path.abspath(path),
                })
        return items

    def get_catalog(self) -> dict:
        return {'items': self.list_tools()}

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
