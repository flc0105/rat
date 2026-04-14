import glob
import os
from pathlib import Path

from werkzeug.utils import secure_filename

from core.utils.script_metadata import read_script_metadata_from_file


class ScriptCatalogService:
    def __init__(self, scripts_root_dir: str):
        self.scripts_root_dir = os.path.abspath(scripts_root_dir)
        self._ensure_dir()

    def _ensure_dir(self):
        os.makedirs(self.scripts_root_dir, exist_ok=True)

    def _normalize_script_name(self, name: str) -> str:
        name = str(name or '').replace('\\', '/').lstrip('/')
        parts = []
        for part in name.split('/'):
            part = part.strip()
            if not part or part in ('.', '..'):
                continue
            parts.append(part)
        normalized = '/'.join(parts)
        if normalized.endswith('.py'):
            return normalized
        return normalized + '.py' if normalized else ''

    def _build_script_item(self, file_path: str) -> dict:
        rel_path = os.path.relpath(file_path, self.scripts_root_dir)
        path = rel_path.replace('\\', '/')
        script_name = path[:-3] if path.endswith('.py') else path
        metadata = read_script_metadata_from_file(file_path, fallback_name=script_name)
        display_name = str(metadata.get('display_name') or Path(path).stem).strip() or Path(path).stem
        description = str(metadata.get('description') or '').strip()
        return {
            'name': script_name,
            'script_name': script_name,
            'path': path,
            'display_name': display_name,
            'description': description,
            'metadata': metadata,
            'size': os.path.getsize(file_path),
            'source': 'script',
            'kind': 'script',
        }

    def list_scripts(self) -> list[dict]:
        items = []
        pattern = os.path.join(self.scripts_root_dir, '**/*.py')
        for file_path in glob.iglob(pattern, recursive=True):
            if not os.path.isfile(file_path):
                continue
            items.append(self._build_script_item(file_path))
        return sorted(items, key=lambda x: x['path'])

    def get_script_content(self, script_name: str) -> str:
        safe_name = self._normalize_script_name(script_name)
        if not safe_name:
            raise ValueError('Invalid script name')
        script_path = os.path.abspath(os.path.join(self.scripts_root_dir, safe_name))
        if not script_path.startswith(self.scripts_root_dir + os.sep):
            raise ValueError('Invalid script path')
        if not os.path.isfile(script_path):
            raise FileNotFoundError(f'Script not found: {script_name}')
        with open(script_path, 'r', encoding='utf-8') as f:
            return f.read()

    def save_script(self, script_name: str, content: str) -> dict:
        safe_name = self._normalize_script_name(script_name)
        if not safe_name:
            raise ValueError('Invalid script name')
        script_path = os.path.abspath(os.path.join(self.scripts_root_dir, safe_name))
        if not script_path.startswith(self.scripts_root_dir + os.sep):
            raise ValueError('Invalid script path')
        os.makedirs(os.path.dirname(script_path), exist_ok=True)
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return {'name': safe_name[:-3], 'path': safe_name, 'size': os.path.getsize(script_path)}

    def delete_script(self, script_name: str) -> dict:
        safe_name = self._normalize_script_name(script_name)
        if not safe_name:
            raise ValueError('Invalid script name')
        script_path = os.path.abspath(os.path.join(self.scripts_root_dir, safe_name))
        if not script_path.startswith(self.scripts_root_dir + os.sep):
            raise ValueError('Invalid script path')
        if not os.path.isfile(script_path):
            raise FileNotFoundError(f'Script not found: {script_name}')
        os.remove(script_path)
        return {'name': safe_name[:-3], 'path': safe_name, 'deleted': True}

    def upload_script(self, file_storage, directory: str = '') -> dict:
        if file_storage is None:
            raise ValueError('file is required')

        original_name = str(getattr(file_storage, 'filename', '') or '').strip()
        if not original_name:
            raise ValueError('filename is required')

        safe_filename = secure_filename(Path(original_name).name)
        if not safe_filename:
            raise ValueError('Invalid filename')
        if not safe_filename.lower().endswith('.py'):
            raise ValueError('Only .py files are supported')

        directory = str(directory or '').replace('\\', '/').strip().strip('/')
        if directory:
            safe_name = self._normalize_script_name(f'{directory}/{safe_filename}')
        else:
            safe_name = self._normalize_script_name(safe_filename)

        if not safe_name:
            raise ValueError('Invalid script name')

        script_path = os.path.abspath(os.path.join(self.scripts_root_dir, safe_name))
        if not script_path.startswith(self.scripts_root_dir + os.sep):
            raise ValueError('Invalid script path')

        os.makedirs(os.path.dirname(script_path), exist_ok=True)
        file_storage.save(script_path)

        return {
            'name': safe_name[:-3],
            'path': safe_name,
            'size': os.path.getsize(script_path),
        }