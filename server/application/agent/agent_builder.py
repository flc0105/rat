import os
import platform
import shutil
import subprocess
import tempfile

from core.utils.logger import logger


class AgentBuilder:
    """Agent 生成器"""

    # 需要排除的目录
    EXCLUDE_DIRS = {'venv', '__pycache__', '.git', 'node_modules', 'dist', 'build', '.idea', '.vscode', 'runtime'}
    EXCLUDE_EXTENSIONS = {'.pyc', '.pyo', '.pyd'}
    SUPPORTED_TARGETS = {'win', 'mac', 'linux'}
    SUPPORTED_BUILDERS = {'pyinstaller', 'go'}
    SUPPORTED_GO_ARCHES = {'auto', 'amd64', 'arm64'}
    PYINSTALLER_PLATFORM_MAP = {
        'Windows': 'win',
        'Darwin': 'mac',
        'Linux': 'linux',
    }
    GO_TARGET_MAP = {
        'win': {'GOOS': 'windows', 'suffix': '.exe', 'label': 'windows'},
        'mac': {'GOOS': 'darwin', 'suffix': '', 'label': 'mac'},
        'linux': {'GOOS': 'linux', 'suffix': '', 'label': 'linux'},
    }

    def __init__(self):
        self.source_dir = os.path.abspath('.')
        self.output_dir = os.path.abspath(os.path.join('runtime', 'agent_output'))
        self._ensure_dirs()

    def _ensure_dirs(self):
        os.makedirs(self.output_dir, exist_ok=True)

    def build_agent(self, server_host: str, server_port: int,
                    web_port: int, target_os: str = 'mac',
                    builder: str = 'pyinstaller', target_arch: str = 'auto') -> dict:
        """
        构建 Agent
        """
        target_os = (target_os or 'mac').strip().lower()
        builder = (builder or 'pyinstaller').strip().lower()
        target_arch = (target_arch or 'auto').strip().lower()

        if target_os not in self.SUPPORTED_TARGETS:
            raise ValueError(f'Unsupported target OS: {target_os}')

        if builder not in self.SUPPORTED_BUILDERS:
            raise ValueError(f'Unsupported builder: {builder}')

        if target_arch not in self.SUPPORTED_GO_ARCHES:
            raise ValueError(f'Unsupported target arch: {target_arch}')

        work_dir = tempfile.mkdtemp(prefix='agent_build_')

        try:
            if builder == 'pyinstaller':
                result = self._build_with_pyinstaller(
                    work_dir=work_dir,
                    server_host=server_host,
                    server_port=server_port,
                    web_port=web_port,
                    target_os=target_os,
                    target_arch=target_arch
                )
            else:
                result = self._build_with_go(
                    work_dir=work_dir,
                    server_host=server_host,
                    server_port=server_port,
                    web_port=web_port,
                    target_os=target_os,
                    target_arch=target_arch
                )

            # 复制产物到输出目录
            output_path = os.path.join(self.output_dir, result['file_name'])
            shutil.copy2(result['file_path'], output_path)

            warnings = result.get('warnings', [])
            if not isinstance(warnings, list):
                warnings = [str(warnings)]

            return {
                'file_path': output_path,
                'file_name': result['file_name'],
                'size': os.path.getsize(output_path),
                'work_dir': work_dir,
                'builder': builder,
                'target_os': target_os,
                'warnings': warnings,
                'target_arch': result.get('target_arch', target_arch),
            }

        except Exception:
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

    def _inject_go_config(self, client_dir: str, server_host: str, server_port: int, web_port: int):
        """直接用模板替换 client-go/config/config.go"""
        config_path = os.path.join(client_dir, 'client-go', 'config', 'config.go')

        template = f'''package config

var SERVER_ADDR = "{server_host}:{server_port}"
var SERVER_WEB_SCHEME = "http"
var SERVER_WEB_HOST = "{server_host}"
var SERVER_WEB_PORT = {web_port}
var UPLOAD_BASE_URL = SERVER_WEB_SCHEME + "://" + SERVER_WEB_HOST + ":" + "{web_port}"
'''

        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(template)

    def _build_with_pyinstaller(self, work_dir: str, server_host: str, server_port: int,
                                web_port: int, target_os: str, target_arch: str = 'auto') -> dict:
        current_target = self._get_current_pyinstaller_target()
        if current_target != target_os:
            current_label = self._describe_target(current_target)
            target_label = self._describe_target(target_os)
            raise ValueError(
                'PyInstaller 仅支持与当前服务端相同平台的打包。'
                f' 当前服务端平台：{current_label}，你选择的是：{target_label}。'
            )

        # 复制客户端源码（排除无用目录）
        client_copy = os.path.join(work_dir, 'rat')
        self._copy_source_with_excludes(self.source_dir, client_copy)
        logger.info(f'临时文件：{os.path.abspath(client_copy)}')

        # 注入配置
        self._inject_config(client_copy, server_host, server_port, web_port)

        # 根据目标系统构建
        if target_os == 'win':
            result = self._build_windows(client_copy, work_dir)
        elif target_os == 'linux':
            result = self._build_linux(client_copy, work_dir)
        else:
            result = self._build_macos(client_copy, work_dir)

        result['warnings'] = [
            'PyInstaller 产物与当前服务端平台一致。'
        ]
        result['target_arch'] = target_arch
        return result

    def _build_with_go(self, work_dir: str, server_host: str, server_port: int,
                       web_port: int, target_os: str, target_arch: str = 'auto') -> dict:
        go_project_dir = os.path.join(self.source_dir, 'client-go')
        if not os.path.isdir(go_project_dir):
            raise FileNotFoundError('client-go directory not found')

        client_copy = os.path.join(work_dir, 'rat')
        self._copy_source_with_excludes(self.source_dir, client_copy)
        logger.info(f'临时文件：{os.path.abspath(client_copy)}')

        self._inject_go_config(client_copy, server_host, server_port, web_port)

        go_target = self.GO_TARGET_MAP[target_os]
        normalized_arch = self._resolve_goarch_for_target(target_os, target_arch)
        output_name = f'ratclient_go_{go_target["label"]}_{normalized_arch}{go_target["suffix"]}'
        output_path = os.path.join(client_copy, 'client-go', output_name)

        env = os.environ.copy()
        env.update({
            'CGO_ENABLED': '0',
            'GOOS': go_target['GOOS'],
            'GOARCH': normalized_arch,
        })

        cmd = [
            'go', 'build',
            '-trimpath',
            '-ldflags', '-s -w',
            '-o', output_path,
            '.',
        ]

        result = subprocess.run(
            cmd,
            cwd=os.path.join(client_copy, 'client-go'),
            capture_output=True,
            text=True,
            env=env
        )

        if result.returncode != 0:
            raise RuntimeError(f'Go build failed: {result.stderr or result.stdout}')

        if not os.path.exists(output_path):
            raise RuntimeError(f'Build output not found: {output_path}')

        if target_os != 'win':
            os.chmod(output_path, 0o755)

        warnings = [
            f'Go 已按目标平台 {self._describe_target(target_os)} 构建，目标架构为 {normalized_arch}。'
        ]
        if target_os == 'win':
            warnings.append('Windows 默认优先打包为 amd64；如果目标机器是 Windows on ARM，请在前台将架构切换为 arm64。')
        elif target_os == 'linux':
            warnings.append('Linux 默认优先打包为 amd64；如果目标机器是 ARM 设备，请在前台将架构切换为 arm64。')
        elif target_os == 'mac':
            warnings.append(
                'macOS 默认会优先选择当前服务端更匹配的架构；如果目标机器架构不同，请在前台手动改为 amd64 或 arm64。')

        return {
            'file_path': output_path,
            'file_name': output_name,
            'warnings': warnings,
            'target_arch': normalized_arch,
        }

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

    def _build_linux(self, client_dir: str, work_dir: str) -> dict:
        """Linux 构建"""
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
            'file_name': 'ratclient_linux'
        }

    def _get_current_pyinstaller_target(self) -> str:
        current_system = platform.system()
        current_target = self.PYINSTALLER_PLATFORM_MAP.get(current_system)
        if not current_target:
            raise ValueError(f'当前服务端平台暂不支持 PyInstaller: {current_system}')
        return current_target

    def _normalize_goarch(self, arch: str) -> str:
        value = (arch or '').strip().lower()
        aliases = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'arm64': 'arm64',
            'aarch64': 'arm64',
            'x64': 'amd64',
        }
        return aliases.get(value, value or 'amd64')

    def _resolve_goarch_for_target(self, target_os: str, target_arch: str = 'auto') -> str:
        """
        根据目标平台和前台选择推导最终 GOARCH

        规则：
        - 前台明确选择 amd64 / arm64 时，直接使用该值
        - auto 模式下：
          - Windows 默认优先 amd64
          - Linux 默认优先 amd64
          - macOS 默认优先当前服务端更匹配的架构
        """
        normalized_target_arch = self._normalize_goarch(target_arch)
        if normalized_target_arch in {'amd64', 'arm64'} and target_arch != 'auto':
            return normalized_target_arch

        current_goarch = os.environ.get('GOARCH', '').strip() or platform.machine().lower()
        normalized_current_arch = self._normalize_goarch(current_goarch)

        if target_os == 'win':
            return 'amd64'

        if target_os == 'linux':
            return 'amd64'

        if target_os == 'mac':
            if normalized_current_arch in {'amd64', 'arm64'}:
                return normalized_current_arch
            return 'arm64'

        return 'amd64'

    def _describe_target(self, target_os: str) -> str:
        mapping = {
            'win': 'Windows',
            'mac': 'macOS',
            'linux': 'Linux',
        }
        return mapping.get(target_os, target_os)

    def cleanup(self, work_dir: str):
        """清理临时目录"""
        if work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)
