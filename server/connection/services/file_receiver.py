class ClientFileReceiver:
    """
    ClientSessionServices 文件接收器。

    职责：
    - 执行底层文件接收
    - 不关心 artifact / history / 回调
    """

    def __init__(self, connection):
        self.connection = connection

    def save_file(self, command_id, filename, length):
        """
        兼容当前调用入口：
        当前正式文件接收由 ArtifactIngestService 编排。
        """
        return self.connection.services.artifact_ingest_service.receive_artifact_file(
            command_id,
            filename,
            length
        )

    def receive_to_io(self, command_id, length, io):
        """
        将指定长度的文件流接收到目标 io 中
        """
        return self.connection.recv_file_packet(command_id, length, io)