from abc import ABC


class CommandBindingMixin:
    """
    命令绑定能力：
    - 持有 socket
    - 持有当前 command_id
    - 持有当前 execution_context
    """

    def __init__(self, socket):
        self.socket = socket
        self.command_id = None
        self.execution_context = None

    def bind_execution(self, command_id, execution_context=None):
        """
        绑定当前命令执行上下文
        """
        self.command_id = command_id
        self.execution_context = execution_context


class CommandResultMixin:
    """
    命令结果发送能力：
    - 负责协议层结果回传
    - 不负责执行时机/业务逻辑
    """

    def _send_result(self, status, result, eof=1):
        """
        发送当前命令的执行结果
        """
        self.socket.send_result(self.command_id, status, result, eof)

    def _send_final_result(self, status, result, eof=1):
        """
        发送最终结果
        """
        self._send_result(status, result, eof)

    def _send_interim_result(self, status, result, eof=0):
        """
        发送中间结果
        """
        self._send_result(status, result, eof)


class CommandRuntimeMixin:
    """
    命令运行时能力：
    - 负责 cancel / timeout / cleanup / interruptible 相关基础设施
    - 不负责协议层输出
    """

    def _get_execution_context(self):
        return self.execution_context

    def _is_cancel_requested(self) -> bool:
        context = self._get_execution_context()
        return bool(context and context.is_cancel_requested())

    def _resolve_timeout(self, fallback_timeout=None):
        context = self._get_execution_context()
        if context is None:
            return fallback_timeout
        return context.resolve_timeout(fallback_timeout)

    def _ensure_not_cancelled(self):
        context = self._get_execution_context()
        if context is None:
            return
        context.raise_if_cancelled()

    def _ensure_not_timed_out(self, fallback_timeout=None):
        context = self._get_execution_context()
        if context is None:
            return
        context.raise_if_timed_out(fallback_timeout=fallback_timeout)

    def _ensure_not_interrupted(self, fallback_timeout=None):
        context = self._get_execution_context()
        if context is None:
            return
        context.raise_if_interrupted(fallback_timeout=fallback_timeout)

    def _set_cancel_policy(self, supported: bool = True, message: str = ''):
        context = self._get_execution_context()
        if context is None:
            return
        context.set_cancel_policy(supported=supported, message=message)

    #add
    def _set_timeout(self, timeout: float):
        """
        设置当前命令的超时时间
        """
        context = self._get_execution_context()
        if context is None:
            return
        context.set_timeout(timeout)

    def _register_cancel_handler(self, handler):
        context = self._get_execution_context()
        if context is None:
            return
        context.add_cancel_handler(handler)

    def _register_cleanup_handler(self, handler):
        context = self._get_execution_context()
        if context is None:
            return
        context.add_cleanup_handler(handler)

    def _cleanup_execution_context(self):
        context = self._get_execution_context()
        if context is None:
            return
        context.run_cleanup()

    def _run_interruptible(self, func, *args, fallback_timeout=None, **kwargs):
        self._ensure_not_interrupted(fallback_timeout=fallback_timeout)
        return func(*args, **kwargs)

    def _iter_interruptible(self, iterable, fallback_timeout=None, check_interval: int = 1):
        interval = max(int(check_interval or 1), 1)
        for index, item in enumerate(iterable, start=1):
            if index == 1 or index % interval == 0:
                self._ensure_not_interrupted(fallback_timeout=fallback_timeout)
            yield item
        self._ensure_not_interrupted(fallback_timeout=fallback_timeout)

    def _read_interruptible(self, file_obj, size=-1, fallback_timeout=None):
        self._ensure_not_interrupted(fallback_timeout=fallback_timeout)
        return file_obj.read(size)

    def _write_interruptible(self, file_obj, data, fallback_timeout=None):
        self._ensure_not_interrupted(fallback_timeout=fallback_timeout)
        return file_obj.write(data)


class CommandBase(
    CommandBindingMixin,
    CommandResultMixin,
    CommandRuntimeMixin,
    ABC,
):
    """命令基类，定义公共接口。"""
    pass








