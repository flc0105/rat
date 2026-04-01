from dataclasses import dataclass


class WebTaskStatus:
    RUNNING = 'running'
    CANCELLING = 'cancelling'
    SUCCESS = 'success'
    ERROR = 'error'
    CANCELLED = 'cancelled'

    ACTIVE_STATUSES = {
        RUNNING,
        CANCELLING,
    }

    TERMINAL_STATUSES = {
        SUCCESS,
        ERROR,
        CANCELLED,
    }


@dataclass
class TaskStreamSummary:
    """
    Web 任务结果流汇总器。

    职责：
    - 统一收口 result stream 的终态判断
    - 区分“失败输出”和“非致命提示输出”
    - 统一推导 success / error / cancelled
    """

    has_failure: bool = False
    has_cancelled_output: bool = False
    has_timeout_output: bool = False

    NON_FATAL_ERROR_TEXTS = {
        'command does not support cancellation',
        'current python execution mode does not support cancellation',
    }

    def record_chunk(self, status: int, text: str):
        normalized_status = int(status or 0)
        normalized_text = str(text or '').strip().lower()

        if 'command cancelled' in normalized_text or normalized_text == 'cancelled':
            self.has_cancelled_output = True

        if 'timed out' in normalized_text:
            self.has_timeout_output = True

        if normalized_status == 0:
            if (
                normalized_text not in self.NON_FATAL_ERROR_TEXTS
                and 'does not support cancellation' not in normalized_text
            ):
                self.has_failure = True

    def mark_exception(self):
        self.has_failure = True

    def is_success(self) -> bool:
        return not self.has_failure

    def resolve_final_status(self, cancel_requested: bool = False) -> str:
        if cancel_requested and (self.has_cancelled_output or self.has_timeout_output):
            return WebTaskStatus.CANCELLED
        return WebTaskStatus.SUCCESS if self.is_success() else WebTaskStatus.ERROR





