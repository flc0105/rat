class ClientSessionContext:
    """
    客户端会话上下文。

    职责：
    - 保存不属于 transport 本体、也不属于 runtime 队列的数据
    - 保存上层（CLI / Web / history / artifact）注入到会话中的上下文能力
    - 保存会话心跳/存活状态信息

    当前承载：
    - is_interactive
    - command_history
    - artifact_service
    - on_unexpected_message
    - on_file_saved
    - on_heartbeat_updated
    - file_save_dir
    - connected_at
    - disconnected_at
    - last_seen_at
    - last_heartbeat_sent_at
    - last_heartbeat_ack_at
    - last_rtt_ms
    - last_heartbeat_id
    """

    def __init__(self, *, file_save_dir=None, on_file_saved=None):
        self.is_interactive = False
        self.command_history = None
        self.artifact_service = None
        self.on_unexpected_message = None
        self.on_heartbeat_updated = None

        self.file_save_dir = file_save_dir
        self.on_file_saved = on_file_saved

        self.connected_at = ''
        self.disconnected_at = ''
        self.last_seen_at = ''
        self.last_heartbeat_sent_at = ''
        self.last_heartbeat_ack_at = ''
        self.last_rtt_ms = None
        self.last_heartbeat_id = None