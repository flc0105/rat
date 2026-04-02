import os


class UploadExecutionService:
    """
    上传执行服务。

    职责：
    - 负责 server -> client 上传链路的 staging / cleanup
    - 负责构建 receive_http_upload 命令负载
    - 负责把“上传”转换成普通远程命令流

    说明：
    - 不负责 foreground 占槽
    - 不负责 history begin/finalize
    - 不负责 task/event publish
    - 只负责 upload 这条执行链路本身
    """

    def __init__(self, server, command_stream_service, artifact_service=None):
        self.server = server
        self.command_stream_service = command_stream_service
        self.artifact_service = artifact_service

    def get_connection(self, target):
        return self.command_stream_service.get_connection(target)

    def _get_artifact_service(self):
        if self.artifact_service is not None:
            return self.artifact_service

        web_service = getattr(self.server, 'web_service', None)
        if web_service is not None:
            artifact_service = getattr(web_service, 'artifact_service', None)
            if artifact_service is not None:
                return artifact_service

        raise RuntimeError('artifact_service is not available on server')

    def stream_upload(
        self,
        target,
        local_path: str,
        *,
        remote_path: str = '',
        history_entry_id: str = '',
        build_http_receive_command,
    ):
        """
        执行上传流。

        流程：
        1. 将 server 本地文件 stage 到 artifact 临时区
        2. 生成 client 可访问的临时 relative_url
        3. 下发 receive_http_upload 远程命令
        4. 将远程命令结果流原样透传
        5. 最后清理 stage 临时文件
        """
        if not (local_path or '').strip():
            raise ValueError('local_path is required')

        session = self.get_connection(target)
        artifact_service = self._get_artifact_service()

        staged_path = ''
        try:
            staged_path, safe_name = artifact_service.stage_local_file(
                local_path,
                display_name=os.path.basename(local_path)
            )
            relative_url = artifact_service.build_upload_temp_download_relative_url(staged_path)

            command = build_http_receive_command({
                'relative_url': relative_url,
                'filename': safe_name,
                'save_dir': remote_path,
            })

            result_iter = self.command_stream_service.stream_command(
                session,
                command,
                command_type='command',
                extra=None,
                history_entry_id=history_entry_id
            )

            for item in result_iter:
                yield item
        finally:
            try:
                artifact_service.cleanup_upload_temp_file(staged_path)
            except Exception:
                pass








