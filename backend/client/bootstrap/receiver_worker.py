import socket
import threading


class ClientReceiverWorker:
    """
    客户端后台接收线程运行器。

    只负责：
    - 启动 / 停止接收线程
    - 持续调用 ServerConnection.recv_message 收包
    - 暂存接收线程里抛出的连接异常
    """

    def __init__(self):
        self._thread = None
        self._stop_event = threading.Event()
        self._error = None
        self._error_lock = threading.Lock()

    def _clear_error(self):
        with self._error_lock:
            self._error = None

    def _set_error(self, error):
        with self._error_lock:
            if self._error is None:
                self._error = error

    def pop_error(self):
        with self._error_lock:
            error = self._error
            self._error = None
            return error

    def stop(self):
        """
        停止接收线程
        """
        self._stop_event.set()

    def reset_runtime(self):
        """
        重置接收线程运行态
        """
        self._stop_event = threading.Event()
        self._clear_error()
        self._thread = None

    def _loop(self, server):
        """
        后台接收线程：
        - 持续 recv 收包
        - 由 ServerConnection 统一决定如何处理消息
        """
        while not self._stop_event.is_set():
            try:
                server.recv_message()
            except socket.error as e:
                if not self._stop_event.is_set():
                    self._set_error(e)
                break
            except Exception as e:
                if not self._stop_event.is_set():
                    self._set_error(e)
                break

    def start(self, server):
        """
        启动后台接收线程
        """
        self._stop_event.clear()
        self._clear_error()

        self._thread = threading.Thread(
            target=self._loop,
            args=(server,),
            name='ClientReceiver',
            daemon=True
        )
        self._thread.start()
