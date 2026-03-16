import queue
import threading
from typing import Dict, List


class WebEventBus:
    """
    简单线程安全事件总线，供 SSE 使用
    """

    def __init__(self):
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.RLock()

    def subscribe(self) -> queue.Queue:
        q = queue.Queue()
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, event_type: str, data: Dict):
        with self._lock:
            subscribers = list(self._subscribers)

        for q in subscribers:
            try:
                q.put_nowait({
                    'event': event_type,
                    'data': data
                })
            except Exception:
                pass