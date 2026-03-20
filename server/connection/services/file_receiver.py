class ClientFileReceiver:
    """
    ClientSessionServices 文件接收器。

    职责：
    - 执行底层文件接收
    - 不关心 artifact / history / 回调
    """

    def __init__(self, session):
        self.session = session

    def save_file(self, command_id, filename, length):
        """
        当前正式文件接收由 ArtifactIngestService 编排。
        """
        return self.session.services.artifact_ingest_service.receive_artifact_file(
            command_id,
            filename,
            length
        )

    def receive_to_io(self, command_id, length, io):
        """
        将指定长度的文件流接收到目标 io 中
        """
        return self.session.recv_file_packet(command_id, length, io)