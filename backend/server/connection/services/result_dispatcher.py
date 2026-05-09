from core.utils.logger import get_file_logger, logger
from server.config.config import BACKGROUND_MESSAGE_LOG_FILE, BACKGROUND_MESSAGE_OUTPUT_TO_FILE

if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
    file_logger = get_file_logger(BACKGROUND_MESSAGE_LOG_FILE)


class ServerResultDispatcher:
    """
    Server 侧结果分发器。

    职责：
    - 判断结果是否属于当前等待中的命令
    - 将预期结果写入结果队列
    - 将非预期结果转成背景消息或未读消息
    """

    def __init__(self, session):
        self.session = session

    def dispatch_result(self, command_id, status, text, end):
        """
        分发命令执行结果
        """
        if self._is_expected_result(command_id):
            self._enqueue_expected_result(status, text, end)
            return

        self._handle_unexpected_message(status, text, end)

    def _enqueue_expected_result(self, status, text, end) -> None:
        """
        将预期命令结果写入结果队列
        """
        self.session.runtime.message_queue.put(status, text, end)

    def _is_expected_result(self, command_id) -> bool:
        """
        判断当前结果是否属于队首等待中的命令
        """
        pending_id = self.session.runtime.pending_command_ids.peek_first()
        return command_id == pending_id

    def _handle_unexpected_message(self, status, text, end):
        """
        处理非预期消息
        """
        callback = self.session.context.on_unexpected_message
        if callable(callback):
            try:
                callback(status, text, end)
            except Exception:
                pass

        # 如果交互态 且开启了背景消息写文件
        if self.session.context.is_interactive:
            if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
                file_logger.info(f'Message from {self.session.address}: {text}')
            else:
                logger.info(text)
            return

        # 非交互态开了背景消息写文件 就只记录到文件 不存未读消息
        if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
            file_logger.info(f'Message from {self.session.address}: {text}')
            return

        # 如果非交互态 没开背景消息 收到消息 直接存储到未读消息
        self.session.runtime.message_queue.put(status, text, end)








