import queue
import threading
from typing import Any, Optional, Tuple


MessageItem = Tuple[int, Any, int]


class BaseThreadSafeQueue:
    """
    线程安全队列基类，封装公共的非阻塞查看、按索引访问、清空等操作
    """

    def __init__(self):
        self._queue = queue.Queue()
        self._lock = threading.Lock()

    def _peek(self) -> Optional[Any]:
        """
        查看队列首元素但不移除
        """
        with self._lock:
            if self._queue.qsize() == 0:
                return None
            return self._queue.queue[0]

    def _clear_internal(self) -> None:
        """
        清空底层队列
        """
        with self._lock:
            self._queue.queue.clear()

    def _get_by_index(self, index: int) -> Any:
        """
        获取指定索引位置的元素但不移除
        """
        with self._lock:
            return self._queue.queue[index]

    def clear(self) -> None:
        """
        清空队列
        """
        self._clear_internal()

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
        return self._get_by_index(index)


class MessageQueue(BaseThreadSafeQueue):
    """
    标准结果消息队列，只存储:
    (status, message, end)
    """

    def get(self, block: bool = True, timeout: Optional[float] = None) -> MessageItem:
        """
        获取并删除队列中的元素
        :param block: 是否阻塞
        :param timeout: 阻塞超时时间
        :return: 元组 (status, message, end)
        """
        return self._queue.get(block=block, timeout=timeout)

    def peek_first(self) -> Optional[MessageItem]:
        """
        获取队列中第一个元素，不删除
        """
        return self._peek()

    def put(self, status: int, message: Any, end: int = 1) -> None:
        """
        向队列中添加标准消息元素
        :param status: 状态
        :param message: 消息
        :param end: 是否结束
        """
        self._queue.put((status, message, end))


class PendingCommandQueue(BaseThreadSafeQueue):
    """
    等待中的命令 ID 队列，只存储 command_id
    """

    def get(self, block: bool = True, timeout: Optional[float] = None) -> int:
        """
        获取并删除队列中的命令 ID
        """
        return self._queue.get(block=block, timeout=timeout)

    def peek_first(self) -> Optional[int]:
        """
        获取队列中第一个命令 ID，不删除
        """
        return self._peek()

    def put(self, command_id: int) -> None:
        """
        向队列中添加命令 ID
        """
        self._queue.put(command_id)


class ReadySignalQueue(BaseThreadSafeQueue):
    """
    文件传输就绪信号队列，只存储 status
    """

    def get(self, block: bool = True, timeout: Optional[float] = None) -> int:
        """
        获取并删除就绪状态
        """
        return self._queue.get(block=block, timeout=timeout)

    def peek_first(self) -> Optional[int]:
        """
        获取队列中第一个就绪状态，不删除
        """
        return self._peek()

    def put(self, status: int) -> None:
        """
        向队列中添加就绪状态
        """
        self._queue.put(status)