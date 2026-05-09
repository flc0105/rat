import os
import tempfile

from core.utils.formatting import get_time


class WinMediaService:
    """
    Windows 截图/媒体能力。
    """

    def __init__(self, owner):
        self.owner = owner

    def capture_screenshot(self):
        temp_file = None
        try:
            import pyautogui

            self.owner._send_interim_result(1, 'Capturing screenshot...', 0)

            # 创建临时文件
            temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
            temp_file.close()

            # 截图
            screenshot = pyautogui.screenshot()
            screenshot.save(temp_file.name)

            file_size = os.path.getsize(temp_file.name)
            self.owner._send_interim_result(1, f'Screenshot captured ({file_size} bytes)', 0)

            # 上传文件
            filename = f'screenshot_{get_time()}.png'
            self.owner.http_file_transfer_service.upload_single_file_to_server_result(
                temp_file.name,
                category='screenshot',
            )

            self.owner._send_final_result(1, f'Screenshot uploaded: {filename}')

        except Exception as e:
            self.owner._send_final_result(0, f'Screenshot failed: {e}')
        finally:
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.unlink(temp_file.name)
                except Exception:
                    pass