import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from core.utils.client_util import get_executable_path
from core.utils.formatting import format_dict, format_table, get_size, get_time


class MacPlatformService:
    """
    macOS 平台能力服务。

    当前承接两类职责：
    - 系统信息采集
    - AppleScript / osascript 基础能力

    扩展后继续承接：
    - 平台命令实现
    - acmd 平台扩展实现

    目标：
    - 让 MacCommands 回到“命令入口层”
    - 让平台能力实现显式下沉到 service，避免平台类持续膨胀
    """

    def __init__(self, owner):
        self.owner = owner

    def run_command_text(self, command: str, timeout: int = 15) -> str:
        try:
            result = self.owner._run_shell_command(command, timeout=timeout)
            if result.returncode != 0:
                return ''
            return (result.stdout or '').strip()
        except Exception:
            return ''

    def build_process_info(self):
        process = psutil.Process()
        executable_path = os.path.realpath(sys.executable)
        script_path = os.path.realpath(''.join(sys.argv))

        return {
            'hostname': platform.node(),
            'macos_version': platform.mac_ver()[0],
            'build_version': self.run_command_text('sw_vers -buildVersion'),
            'architecture': platform.machine(),
            'hardware_model': self.run_command_text('sysctl -n hw.model'),
            'cpu_brand': self.run_command_text('sysctl -n machdep.cpu.brand_string'),
            'cpu_cores': os.cpu_count(),
            'memory': f'{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB',
            'python_version': platform.python_version(),
            'process_id': os.getpid(),
            'current_user': process.username(),
            'launch_command': f'{executable_path} {script_path}',
            'process_uptime': f'{round(time.time() - process.create_time(), 2)}s',
            'cwd': os.getcwd()
        }

    def escape_osascript_text(self, value: str):
        text = str(value or '')
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        return text

    def spawn_osascript(self, applescript: str):
        process = subprocess.Popen(
            ['osascript', '-e', applescript],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        self.owner._register_cancel_handler(lambda: self.owner._terminate_process(process))
        return process

    # ------------------ 普通平台命令实现 ------------------ #
    def capture_screenshot(self):
        screenshot_path = f'screenshot_{get_time()}.png'
        capture_command = f'screencapture -x {screenshot_path}'

        try:
            self.owner._send_interim_result(1, f'Capturing screen: {capture_command}')
            result = self.owner._run_shell_command(capture_command, timeout=15)
            if result.returncode != 0:
                return 0, result.stderr or 'Failed to capture screenshot'

            self.owner._send_interim_result(1, 'Screenshot captured successfully', 0)
            return self.owner._upload_single_file_to_server_result(screenshot_path, category='screenshot')
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

    # def collect_system_info(self):
    #     try:
    #         payload = self.owner._run_interruptible(self.build_process_info)
    #         return 1, format_dict(payload)
    #     except CommandCancelledError:
    #         return 0, 'Command cancelled'
    #     except CommandTimeoutError:
    #         return 0, 'Command timed out and was terminated'
    #     except Exception as e:
    #         return 0, f'Failed to collect system information: {e}'

    def collect_system_info(self, arg=''):
        try:
            payload = self.owner._run_interruptible(self.build_process_info)

            arg_text = str(arg or '').strip().lower()
            output_json = arg_text in ('json', '--json')

            if output_json:
                return 1, json.dumps(payload, ensure_ascii=False, indent=2)

            return 1, format_dict(payload)
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to collect system information: {e}'

    def get_idle_time(self):
        try:
            from Quartz import (
                CGEventSourceSecondsSinceLastEventType,
                kCGAnyInputEventType,
                kCGEventSourceStateHIDSystemState,
            )

            idle_seconds = self.owner._run_interruptible(
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

    def capture_webcam_photo(self):
        """拍照并上传到服务器"""
        temp_file = None

        try:
            result = subprocess.run(['which', 'imagesnap'], capture_output=True)
            if result.returncode != 0:
                return 0, '请安装 imagesnap: brew install imagesnap'

            temp_file = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False)
            temp_file.close()

            subprocess.run(
                ['imagesnap', '-w', '1', temp_file.name],
                capture_output=True,
                timeout=5
            )

            if os.path.getsize(temp_file.name) > 0:
                self.owner._upload_single_file_to_server_result(temp_file.name, category='webcam')
                file_size = get_size(os.path.getsize(temp_file.name))
                return 1, f'Webcam photo captured: {temp_file.name} ({file_size})'

            return 0, 'Failed to capture webcam photo'
        except Exception as e:
            return 0, f'Webcam capture failed: {e}'
        finally:
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.unlink(temp_file.name)
                except Exception:
                    pass

    def sudo_self(self):
        """以 root 权限启动新实例，返回 PID"""
        cmd = get_executable_path()

        # 使用 osascript 启动，不等待
        proc = subprocess.Popen(
            ['osascript', '-e', f'do shell script "{cmd}" with administrator privileges'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return 1, f'New instance launched with sudo (parent PID: {proc.pid})'

    def sudo_run(self, command):
        """以 root 权限执行命令 (macOS)"""
        try:
            result = subprocess.run(
                ['osascript', '-e', f'do shell script "{command}" with administrator privileges'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return 1, result.stdout
            return 0, result.stderr
        except Exception as e:
            return 0, f'Failed: {e}'

    def secure_delete_file(self, path):
        """安全删除文件（覆写后删除）"""
        try:
            target = self.owner._resolve_target_path(path)
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'

            if os.path.isdir(target):
                return 0, 'Use rmdir for directories'

            # 获取文件大小
            size = os.path.getsize(target)

            self.owner._send_interim_result(1, f'Shredding {target} ({size} bytes)', 0)

            # 多次覆写
            with open(target, 'r+b') as f:
                for _ in range(3):
                    self.owner._ensure_not_interrupted()
                    f.seek(0)
                    # 第一次: 0x00
                    f.write(b'\x00' * size)
                    f.flush()

                    self.owner._ensure_not_interrupted()
                    f.seek(0)
                    # 第二次: 0xFF
                    f.write(b'\xFF' * size)
                    f.flush()

                    self.owner._ensure_not_interrupted()
                    f.seek(0)
                    # 第三次: 随机数据
                    f.write(os.urandom(size))
                    f.flush()

            # 最后删除
            os.remove(target)

            return 1, f'File securely deleted: {target}'

        except Exception as e:
            return 0, f'Failed to shred file: {e}'

    def volume(self, level=None):
        """获取或设置系统音量 (0-100)"""
        try:
            if level is None or level == '':
                result = subprocess.run(
                    ['osascript', '-e', 'output volume of (get volume settings)'],
                    capture_output=True,
                    text=True
                )
                current = result.stdout.strip()
                return 1, f'Current volume: {current}'

            level = int(level)
            if level < 0:
                level = 0
            elif level > 100:
                level = 100

            subprocess.run(
                ['osascript', '-e', f'set volume output volume {level}'],
                capture_output=True
            )
            return 1, f'Volume set to {level}'
        except Exception as e:
            return 0, f'Failed: {e}'

    # ------------------ acmd 平台扩展实现 ------------------ #
    def acmd_msgbox(self, args_dict, payload=None):
        try:
            title = args_dict.get('title', '')
            text = args_dict['text']
            timeout = args_dict.get('timeout')

            escaped_text = self.escape_osascript_text(text)
            escaped_title = self.escape_osascript_text(title)

            applescript = (
                f'display dialog "{escaped_text}" '
                f'with title "{escaped_title}" buttons {{"OK"}} default button "OK"'
            )
            if timeout is not None and timeout > 0:
                applescript += f' giving up after {timeout}'

            process = self.spawn_osascript(applescript)
            return 1, f'Message box launched asynchronously: {title or "(no title)"}\nPID: {process.pid}'
        except Exception as e:
            return 0, f'Failed to launch message box: {e}'

    def acmd_notify(self, args_dict, payload=None):
        try:
            title = args_dict.get('title', '')
            text = args_dict['text']
            sound = args_dict.get('sound', False)

            escaped_text = self.escape_osascript_text(text)
            escaped_title = self.escape_osascript_text(title)

            applescript = f'display notification "{escaped_text}"'
            if escaped_title:
                applescript += f' with title "{escaped_title}"'
            if sound:
                applescript += ' sound name "default"'

            process = self.spawn_osascript(applescript)
            return 1, f'Notification launched asynchronously: {title or "(no title)"}\nPID: {process.pid}'
        except Exception as e:
            return 0, f'Failed to launch notification: {e}'

    def acmd_sqlite_query(self, args_dict, payload=None):
        """
        只读 SQLite 查询
        Examples:
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_list;"
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_info('bookings')"
            acmd sqlite_query --db /Users/flc/studio.db --query "select * from scenes"
        """
        try:
            import sqlite3

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

            return 1, format_table(headers, data)

        except Exception as e:
            error_name = e.__class__.__name__
            if error_name == 'Error':
                return 0, f'SQLite error: {e}'
            return 0, f'Query failed: {e}'

    def acmd_image_info(self, args_dict, payload=None):
        """获取图片信息"""
        try:
            from fractions import Fraction

            from PIL import Image

            def _normalize_exif_value(value, tag=None):
                """
                将 EXIF 值转换为可读、可 JSON 序列化的基础类型
                """
                if isinstance(value, bytes):
                    return value.decode('utf-8', errors='replace')

                if isinstance(value, tuple):
                    return [_normalize_exif_value(item, tag=tag) for item in value]

                if tag == 40961:
                    return 'sRGB' if value == 1 else 'Uncalibrated'

                # 兼容 Pillow 的 IFDRational / 其他 Rational 类型
                try:
                    if isinstance(value, Fraction):
                        if value.denominator == 1:
                            return value.numerator
                        return float(value)
                except Exception:
                    pass

                # 某些 IFDRational 不是 Fraction 子类，这里再兜一层
                if hasattr(value, 'numerator') and hasattr(value, 'denominator'):
                    try:
                        numerator = value.numerator
                        denominator = value.denominator
                        if denominator == 1:
                            return int(numerator)
                        return float(value)
                    except Exception:
                        return str(value)

                # 兜底：保证 json.dumps 不炸
                if isinstance(value, (str, int, float, bool)) or value is None:
                    return value

                return str(value)

            img_path = args_dict.get('path', '')
            output_json = args_dict.get('json', False)

            if not img_path:
                return 0, 'path is required'

            if not os.path.isfile(img_path):
                return 0, f'File not found: {img_path}'

            img = Image.open(img_path)

            info = {
                'path': img_path,
                'width': img.width,
                'height': img.height,
                'size': f'{img.width}x{img.height}',
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
                        info[exif_tags[tag]] = _normalize_exif_value(value, tag=tag)

            img.close()

            if output_json:
                return 1, json.dumps(info, ensure_ascii=False, indent=2)

            return 1, format_dict(info, width=30)

        except ImportError:
            return 0, 'PIL not installed, install with: pip install Pillow'
        except Exception as e:
            return 0, f'Failed to get image info: {e}'

    def acmd_import_check(self, args_dict, payload=None):
        """检查 Python 包是否可以导入"""
        try:
            import importlib
            import importlib.metadata

            module_name = args_dict.get('module', '')

            if not module_name:
                return 0, 'module name is required'

            result = {
                'module': module_name,
                'importable': False,
                'module_path': None,
                'module_version': None,
                'package_name': None,
                'package_version': None,
                'package_dependencies': []
            }

            try:
                module = importlib.import_module(module_name)
                result['importable'] = True
                result['module_path'] = getattr(module, '__file__', None)

                for attr in ['__version__', 'version', 'VERSION']:
                    if hasattr(module, attr):
                        result['module_version'] = str(getattr(module, attr))
                        break

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
                        except Exception:
                            continue

            except ImportError as e:
                result['error'] = str(e)

            return 1, format_dict(result)

        except Exception as e:
            return 0, f'Check failed: {e}'

    def acmd_archive_peek(self, args_dict, payload=None):
        """查看压缩包内容"""
        try:
            import tarfile
            import zipfile

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
                            'date': f'{info.date_time[0]}-{info.date_time[1]:02d}-{info.date_time[2]:02d}'
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

            result = format_table(headers, data)

            if len(entries) >= limit:
                result += f'\n... and more (limited to {limit})'

            return 1, result

        except Exception as e:
            return 0, f'Failed to peek archive: {e}'