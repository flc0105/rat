import json


class RemoteCommandRunner:
    """
    统一远程命令调用器。

    职责：
    - 根据 client_id 获取连接
    - 执行远程命令
    - 收集文本结果
    - 提供 JSON 结果解析
    """

    def __init__(self, server):
        self.server = server

    def get_connection(self, client_id: str):
        return self.server.get_target_connection_by_client_id(client_id)

    def collect_result(self, result_iter):
        final_status = 1
        parts = []

        for status, text in result_iter:
            final_status = status
            if text is not None:
                parts.append(str(text))

        return final_status, '\n'.join(part for part in parts if part).strip()

    def run_text_command(self, client_id: str, command: str) -> str:
        conn = self.get_connection(client_id)
        status, text = self.collect_result(conn.send_command(command))

        if status != 1:
            raise RuntimeError(text or 'Remote command failed')

        return text

    def run_json_command(self, client_id: str, command: str) -> dict:
        text = self.run_text_command(client_id, command)

        try:
            payload = json.loads(text or '{}')
        except Exception as e:
            raise RuntimeError(f'Invalid remote JSON payload: {e}')

        if not isinstance(payload, dict):
            raise RuntimeError('Invalid remote JSON payload: expected object')

        return payload


class RemoteArtifactFetcher:
    """
    统一远程 artifact 拉取器。

    职责：
    - 为指定 command_id 配置文件接收上下文
    - 发送远程命令
    - 等待 artifact 落地
    - 返回 artifact + 命令消息
    """

    def __init__(self, server):
        self.server = server

    def get_connection(self, client_id: str):
        return self.server.get_target_connection_by_client_id(client_id)

    def collect_result(self, result_iter):
        final_status = 1
        parts = []

        for status, text in result_iter:
            final_status = status
            if text is not None:
                parts.append(str(text))

        return final_status, '\n'.join(part for part in parts if part).strip()

    def fetch_artifact(
        self,
        client_id: str,
        command: str,
        *,
        artifact_type: str,
        source_type: str,
        related_path: str = '',
        category: str = '',
        extra: dict | None = None,
    ) -> dict:
        conn = self.get_connection(client_id)
        command_id = conn._generate_message_id()
        capture_result = {}

        conn.set_file_receive_context(
            command_id,
            artifact_type=artifact_type,
            category=category,
            source_type=source_type,
            related_path=related_path,
            source_command_id=command_id,
            capture_result=capture_result,
            extra=extra or {},
        )

        conn.send({
            'type': 'command',
            'id': command_id,
            'text': command,
        })

        status, text = self.collect_result(conn.wait_for_result(command_id, command))
        if status != 1:
            raise RuntimeError(text or 'Remote file fetch failed')

        artifact = capture_result.get('artifact') or {}
        if not isinstance(artifact, dict) or not artifact.get('artifact_id'):
            raise RuntimeError('Remote file download completed, but artifact was not found')

        return {
            'message': text,
            'artifact': artifact,
        }