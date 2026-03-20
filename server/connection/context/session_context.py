class ClientSessionContext:
    """
    客户端会话上下文。

    职责：
    - 保存不属于 transport 本体、也不属于 runtime 队列的数据
    - 保存上层（CLI / Web / history / artifact）注入到会话中的上下文能力

    当前承载：
    - is_interactive
    - command_history
    - artifact_service
    - on_unexpected_message
    - on_file_saved
    - file_save_dir
    """

    def __init__(self, *, file_save_dir=None, on_file_saved=None):
        self.is_interactive = False
        self.command_history = None
        self.artifact_service = None
        self.on_unexpected_message = None

        self.file_save_dir = file_save_dir
        self.on_file_saved = on_file_saved