class ReadyFileTransferMixin:
    """
    文件发送相关通用能力：
    - 等待指定 command_id 的 ready 信号
    - 发送 file header -> wait ready -> send io
    """

    FILE_READY_TIMEOUT = 15.0
    FILE_TRANSFER_REJECTED_MESSAGE = 'Peer rejected file transfer'

    def _wait_for_ready_signal(self, command_id: int, timeout: float | None = None) -> int:
        """
        等待指定命令对应的文件传输 ready 信号
        """
        effective_timeout = self.FILE_READY_TIMEOUT if timeout is None else timeout
        try:
            return self.ready_queue.get_for_command(command_id, timeout=effective_timeout)
        except Exception:
            raise TimeoutError(f'Timed out waiting for ready signal: command_id={command_id}')

    def _send_file_with_ready(self, header: dict, io):
        """
        统一的文件发送流程：
        - 发送文件头
        - 等待对应 command_id 的 ready
        - 发送文件流
        """
        command_id = header.get('id')

        try:
            self.send(header)
            if self._wait_for_ready_signal(command_id):
                self.send_io(io)
            else:
                io.close()
                raise RuntimeError(f'{self.FILE_TRANSFER_REJECTED_MESSAGE}: command_id={command_id}')
        except Exception:
            try:
                io.close()
            except Exception:
                pass
            raise


class ReceiverDispatchMixin:
    """
    接收线程统一入口：
    - recv 一条消息
    - 交给 handle_received_message 处理
    - 如果返回结果元组，则立即 send_result
    """

    def recv_message(self):
        """
        接收线程统一入口
        """
        data = self.recv()
        result = self.handle_received_message(data)
        if result:
            self.send_result(*result)