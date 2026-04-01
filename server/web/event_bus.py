import queue
import threading
from typing import Dict, List


class WebEventBus:
    """
    简单线程安全事件总线，供 SSE 使用。

    支持：
    - 全局广播事件
    - 按 tab_id 定向推送事件

    设计原则：
    - 连接状态 / artifact / background job 等全局事件继续广播
    - 前台命令输出类事件可按 tab_id 定向，避免多个浏览器页签互相污染
    """

    def __init__(self):
        self._subscribers: List[dict] = []
        self._lock = threading.RLock()

    def subscribe(self, tab_id: str = '') -> queue.Queue:
        q = queue.Queue()
        subscriber = {
            'queue': q,
            'tab_id': str(tab_id or '').strip(),
        }
        with self._lock:
            self._subscribers.append(subscriber)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            self._subscribers = [
                item for item in self._subscribers
                if item.get('queue') is not q
            ]

    def _should_deliver(self, subscriber: dict, target_tab_id: str) -> bool:
        normalized_target_tab_id = str(target_tab_id or '').strip()
        if not normalized_target_tab_id:
            return True

        subscriber_tab_id = str(subscriber.get('tab_id') or '').strip()
        return subscriber_tab_id == normalized_target_tab_id

    def publish(self, event_type: str, data: Dict, target_tab_id: str = ''):
        event_item = {
            'event': event_type,
            'data': data
        }

        with self._lock:
            subscribers = list(self._subscribers)

        for subscriber in subscribers:
            if not self._should_deliver(subscriber, target_tab_id):
                continue

            q = subscriber.get('queue')
            if q is None:
                continue

            try:
                q.put_nowait(event_item)
            except Exception:
                pass





