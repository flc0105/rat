import glob
import os


class ServerJobService:

    def __init__(self, scripts_root_dir: str):
        self.scripts_root_dir = os.path.abspath(scripts_root_dir)
        self._ensure_dir()

    def _ensure_dir(self):
        """确保脚本目录存在"""
        os.makedirs(self.scripts_root_dir, exist_ok=True)

    def list_scripts(self) -> list[dict]:
        """
        列出所有可用的脚本
        """
        scripts = []
        pattern = os.path.join(self.scripts_root_dir, '**/*.py')
        for file_path in glob.iglob(pattern, recursive=True):
            if os.path.isfile(file_path):
                rel_path = os.path.relpath(file_path, self.scripts_root_dir)
                name = rel_path.replace('\\', '/')
                scripts.append({
                    'job_name': name,
                    'job_key': name,
                    'path': file_path,
                    'size': os.path.getsize(file_path),
                    'source': 'server'
                })
        return sorted(scripts, key=lambda x: x['job_name'])

    def get_script_content(self, script_name: str) -> str:
        """
        获取脚本内容
        """
        # 安全检查：防止路径遍历攻击
        safe_name = self._normalize_script_name(script_name)
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
        # 移除开头的 / 或 \
        name = name.lstrip('/\\')
        # 移除 .. 等危险路径
        parts = []
        for part in name.split('/'):
            if part == '..':
                continue
            parts.append(part)
        return '/'.join(parts)

    def save_script(self, script_name: str, content: str) -> dict:
        """
        保存脚本（用于前端新建）
        """
        safe_name = self._normalize_script_name(script_name)
        script_path = os.path.join(self.scripts_root_dir, safe_name)

        # 确保目录存在
        os.makedirs(os.path.dirname(script_path), exist_ok=True)

        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return {
            'name': safe_name,
            'path': script_path,
            'size': os.path.getsize(script_path),
        }






