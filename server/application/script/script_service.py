import glob
import os
from pathlib import Path

from werkzeug.utils import secure_filename


class ServerJobService:

    def __init__(self, scripts_root_dir: str):
        self.scripts_root_dir = os.path.abspath(scripts_root_dir)
        self._ensure_dir()

    def _ensure_dir(self):
        """确保脚本目录存在"""
        os.makedirs(self.scripts_root_dir, exist_ok=True)

    def list_scripts(self) -> list[dict]:
        """列出所有可用的脚本。"""
        scripts = []
        pattern = os.path.join(self.scripts_root_dir, '**/*.py')
        for file_path in glob.iglob(pattern, recursive=True):
            if not os.path.isfile(file_path):
                continue
            rel_path = os.path.relpath(file_path, self.scripts_root_dir)
            name = rel_path.replace('\\', '/')
            job_name = name[:-3] if name.endswith('.py') else name
            scripts.append({
                'name': job_name,
                'job_name': job_name,
                'job_key': job_name,
                'display_name': name,
                'path': file_path,
                'size': os.path.getsize(file_path),
                'source': 'server',
                'kind': 'server_script',
            })
        return sorted(scripts, key=lambda x: x['job_name'])

    def get_script_content(self, script_name: str) -> str:
        """
        获取脚本内容
        """
        # 安全检查：防止路径遍历攻击
        safe_name = self._normalize_script_name(script_name)
        if not safe_name:
            raise ValueError('Invalid script name')
        script_path = os.path.join(self.scripts_root_dir, safe_name)
        script_path = os.path.abspath(script_path)

        # 确保路径在 scripts_root_dir 内
        if not script_path.startswith(self.scripts_root_dir + os.sep):
            raise ValueError('Invalid script path')

        if not os.path.isfile(script_path):
            raise FileNotFoundError(f'Script not found: {script_name}')

        with open(script_path, 'r', encoding='utf-8') as f:
            return f.read()

    def _normalize_script_name(self, name: str) -> str:
        """
        规范化脚本名称，防止路径遍历
        """
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

    def _resolve_script_path_for_write(self, script_name: str) -> tuple[str, str]:
        safe_name = self._normalize_script_name(script_name)
        if not safe_name:
            raise ValueError('Invalid script name')

        script_path = os.path.abspath(os.path.join(self.scripts_root_dir, safe_name))
        if not script_path.startswith(self.scripts_root_dir + os.sep):
            raise ValueError('Invalid script path')

        os.makedirs(os.path.dirname(script_path), exist_ok=True)
        return safe_name, script_path

    def save_script(self, script_name: str, content: str) -> dict:
        """
        保存脚本（用于前端编辑 / 新建）
        """
        safe_name, script_path = self._resolve_script_path_for_write(script_name)

        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return {
            'name': safe_name,
            'path': script_path,
            'size': os.path.getsize(script_path),
        }

    def upload_script(self, file_storage) -> dict:
        """上传一个 .py 脚本到 server jobs 目录。"""
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

        safe_name, script_path = self._resolve_script_path_for_write(safe_filename)
        file_storage.save(script_path)

        return {
            'name': safe_name,
            'path': script_path,
            'size': os.path.getsize(script_path),
        }

    def _resolve_script_path(self, script_name: str) -> tuple[str, str]:
        """
        解析脚本路径（读取/删除用）
        """
        safe_name = self._normalize_script_name(script_name)
        if not safe_name:
            raise ValueError('Invalid script name')

        script_path = os.path.abspath(os.path.join(self.scripts_root_dir, safe_name))
        if not script_path.startswith(self.scripts_root_dir + os.sep):
            raise ValueError('Invalid script path')

        return safe_name, script_path

    def delete_script(self, script_name: str) -> dict:
        """
        删除一个 server-side job 脚本
        """
        safe_name, script_path = self._resolve_script_path(script_name)

        if not os.path.isfile(script_path):
            raise FileNotFoundError(f'Script not found: {script_name}')

        os.remove(script_path)

        return {
            'name': safe_name[:-3] if safe_name.endswith('.py') else safe_name,
            'display_name': safe_name,
            'path': script_path,
            'deleted': True,
        }









