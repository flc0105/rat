import queue
import threading
from typing import Optional, Tuple, Any, Union


class MessageQueue:
    """
    线程安全消息队列，用于存储命令结果或其他消息。
    支持 peek、清空、状态专用方法。
    """

    def __init__(self):
        self._queue = queue.Queue()
        self._lock = threading.Lock()

    def get(self, block: bool = True, timeout: Optional[float] = None) -> Tuple[int, Any, int]:
        """
        获取并删除队列中的元素
        :param block: 是否阻塞
        :param timeout: 阻塞超时时间
        :return: 元组 (status, message, end)
        """
        return self._queue.get(block=block, timeout=timeout)

    def peek_first(self) -> Optional[Union[Tuple[int, Any, int], Any]]:
        """
        获取队列中第一个元素，不删除
        :return: 元素或 None
        """
        with self._lock:
            if self._queue.qsize() == 0:
                return None
            return self._queue.queue[0]

    def get_status(self):
        """
        获取并删除队列中的元素，返回 status
        :return: 队列中的元素的 status
        """
        return self._queue.get()[0]

    def put(self, status: int, message: Any, end: int = 1):
        """
        向队列中添加元素
        :param status: 状态
        :param message: 消息
        :param end: 是否结束
        """
        self._queue.put((status, message, end))

    def put_status(self, status: int):
        """
        向队列中添加状态专用元素 (message=None)
        """
        self.put(status, None, 1)

    def put_command_id(self, command_id: int):
        """
        向队列中添加命令ID
        """
        self._queue.put(command_id)

    def clear(self):
        """
        清空队列
        """
        with self._lock:
            self._queue.queue.clear()

    def empty(self) -> bool:
        """
        判断队列是否为空
        """
        return self._queue.empty()

    def __len__(self) -> int:
        """
        返回队列长度
        """
        return self._queue.qsize()

    def __getitem__(self, index: int) -> Any:
        """
        获取队列中指定索引元素，不删除
        """
        with self._lock:
            return self._queue.queue[index]
