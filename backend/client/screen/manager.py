import base64
import io
import threading
import time

from core.protocol.message_types import (
    MSG_TYPE_SCREEN_CLOSED,
    MSG_TYPE_SCREEN_ERROR,
    MSG_TYPE_SCREEN_FRAME,
    MSG_TYPE_SCREEN_OPENED,
)
from core.utils.logger import logger


class ScreenViewManager:
    """
    Client 端只读屏幕预览管理器。

    当前只负责截图和帧传输，不接收鼠标/键盘输入。
    """

    MIN_FPS = 1
    MAX_FPS = 10
    MIN_QUALITY = 20
    MAX_QUALITY = 95

    def __init__(self, connection):
        self.connection = connection
        self._lock = threading.RLock()
        self._sessions = {}

    def open_session(self, screen_session_id: str, fps: int = 4, quality: int = 60):
        session_id = str(screen_session_id or '').strip()
        if not session_id:
            return False

        self.close_session(session_id, notify=False)

        item = {
            'screen_session_id': session_id,
            'fps': self._normalize_fps(fps),
            'quality': self._normalize_quality(quality),
            'stop_event': threading.Event(),
            'notify_on_close': True,
            'thread': None,
        }

        worker = threading.Thread(
            target=self._capture_loop,
            args=(session_id,),
            daemon=True,
            name=f'screen-view-{session_id[:8]}',
        )
        item['thread'] = worker

        with self._lock:
            self._sessions[session_id] = item

        self.connection.send({
            'type': MSG_TYPE_SCREEN_OPENED,
            'screen_session_id': session_id,
            'fps': item['fps'],
            'quality': item['quality'],
        })
        worker.start()
        return True

    def update_session(self, screen_session_id: str, fps=None, quality=None):
        session_id = str(screen_session_id or '').strip()
        with self._lock:
            item = self._sessions.get(session_id)
            if not item:
                return False
            if fps is not None:
                item['fps'] = self._normalize_fps(fps)
            if quality is not None:
                item['quality'] = self._normalize_quality(quality)
        return True

    def close_session(self, screen_session_id: str, notify: bool = True):
        session_id = str(screen_session_id or '').strip()
        with self._lock:
            item = self._sessions.get(session_id)
            if not item:
                return False
            item['notify_on_close'] = bool(notify)
            item['stop_event'].set()
        return True

    def close_all_sessions(self, notify: bool = True):
        with self._lock:
            session_ids = list(self._sessions.keys())
        for session_id in session_ids:
            self.close_session(session_id, notify=notify)

    def _capture_loop(self, screen_session_id: str):
        failed = False
        try:
            while True:
                with self._lock:
                    item = self._sessions.get(screen_session_id)
                    if not item:
                        return
                    stop_event = item['stop_event']
                    fps = item['fps']
                    quality = item['quality']

                if stop_event.is_set():
                    break

                started_at = time.monotonic()
                image = self._capture_image()
                frame_bytes, width, height = self._encode_jpeg(image, quality)

                self.connection.send({
                    'type': MSG_TYPE_SCREEN_FRAME,
                    'screen_session_id': screen_session_id,
                    'data': base64.b64encode(frame_bytes).decode('ascii'),
                    'width': int(width),
                    'height': int(height),
                    'bytes': len(frame_bytes),
                    'captured_at': time.time(),
                })

                elapsed = time.monotonic() - started_at
                delay = max(0.0, (1.0 / max(1, fps)) - elapsed)
                if stop_event.wait(delay):
                    break
        except Exception as e:
            failed = True
            logger.error(f'Screen view capture failed: {e}', exc_info=True)
            try:
                self.connection.send({
                    'type': MSG_TYPE_SCREEN_ERROR,
                    'screen_session_id': screen_session_id,
                    'message': str(e or 'Screen capture failed'),
                })
            except Exception:
                pass
        finally:
            notify = False
            with self._lock:
                item = self._sessions.pop(screen_session_id, None)
                if item:
                    notify = bool(item.get('notify_on_close'))

            if notify and not failed:
                try:
                    self.connection.send({
                        'type': MSG_TYPE_SCREEN_CLOSED,
                        'screen_session_id': screen_session_id,
                    })
                except Exception:
                    pass

    def _capture_image(self):
        image_grab_error = None
        try:
            from PIL import ImageGrab
            try:
                return ImageGrab.grab(all_screens=True)
            except TypeError:
                return ImageGrab.grab()
        except Exception as e:
            image_grab_error = e

        try:
            import pyautogui
            return pyautogui.screenshot()
        except Exception as e:
            if image_grab_error is not None:
                raise RuntimeError(f'Pillow ImageGrab failed: {image_grab_error}; pyautogui failed: {e}')
            raise RuntimeError(f'Screen capture failed: {e}')

    def _encode_jpeg(self, image, quality: int):
        if image is None:
            raise RuntimeError('Screen capture returned no image')

        if getattr(image, 'mode', '') != 'RGB':
            image = image.convert('RGB')

        buffer = io.BytesIO()
        image.save(
            buffer,
            format='JPEG',
            quality=self._normalize_quality(quality),
            optimize=False,
        )
        return buffer.getvalue(), image.width, image.height

    def _normalize_fps(self, value) -> int:
        try:
            normalized = int(value)
        except Exception:
            normalized = 4
        return max(self.MIN_FPS, min(self.MAX_FPS, normalized))

    def _normalize_quality(self, value) -> int:
        try:
            normalized = int(value)
        except Exception:
            normalized = 60
        return max(self.MIN_QUALITY, min(self.MAX_QUALITY, normalized))
