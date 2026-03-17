import os
import shutil
import threading
from datetime import datetime

from server.commands.executor import CommandExecutor
from server.connection.client_connection import ClientConnection
from server.web.event_bus import WebEventBus
from server.web.file_service import WebFileService
from server.web.task_store import WebTaskStore


class ServerWebService:
    """
    Server 的 Web 应用层服务。

    职责：
    - 面向前端提供连接信息序列化
    - 提交并执行 Web 命令 / 上传任务
    - 管理 Web 任务状态
    - 发布 SSE 事件
    - 为连接安装 Web 侧回调
    - 协调文件服务
    """

    def __init__(self, server):
        self.server = server
        self.event_bus = WebEventBus()
        self.task_store = WebTaskStore()
        self.file_service = WebFileService()

    # ------------------ file notifications ------------------ #
    def notify_file_received(self, client_id: str, original_name: str, saved_path: str, size: int):
        self.event_bus.publish('file_received', {
            'client_id': client_id,
            'original_name': original_name,
            'saved_name': os.path.basename(saved_path),
            'saved_path': saved_path,
            'size': size,
            'created_at': datetime.now().isoformat(),
        })

    # ------------------ connections payload ------------------ #
    def serialize_connection(self, conn: ClientConnection) -> dict:
        info = conn.info or {}
        return {
            'client_id': info.get('id'),
            'addr': info.get('addr', ''),
            'os_type': info.get('os_type', 'Unknown'),
            'os_ver': info.get('os_ver', 'Unknown'),
            'hostname': info.get('hostname', 'Unknown'),
            'integrity': info.get('integrity', '?'),
            'cwd': info.get('cwd', ''),
        }

    def get_connections_payload(self):
        return [self.serialize_connection(conn) for conn in self.server.connections.all()]

    # ------------------ connection hooks ------------------ #
    def build_connection(self, conn, addr, info: dict) -> ClientConnection:
        """
        创建并配置带 Web 能力的客户端连接对象
        """
        connection = ClientConnection(
            conn,
            addr,
            info,
            file_save_dir=self.file_service.received_files_dir,
            on_file_saved=lambda original_name, saved_path, size: self.notify_file_received(
                info.get('id'),
                original_name,
                saved_path,
                size
            )
        )

        connection.on_unexpected_message = (
            lambda status, text, end: self.publish_background_message(connection, status, text, end)
        )
        return connection

    def on_connection_registered(self, connection: ClientConnection):
        """
        连接注册成功后的 Web 通知
        """
        self.publish_connection_online(connection)

    def on_connection_closed(self, conn: ClientConnection):
        """
        连接关闭后的 Web 通知
        """
        self.publish_connection_offline(conn)

    # ------------------ event publish ------------------ #
    def publish_connection_online(self, connection: ClientConnection):
        self.event_bus.publish('connection_online', {
            'connection': self.serialize_connection(connection),
            'time': datetime.now().isoformat()
        })

    def publish_connection_offline(self, conn: ClientConnection):
        self.event_bus.publish('connection_offline', {
            'client_id': conn.info.get('id'),
            'time': datetime.now().isoformat()
        })

    def publish_background_message(self, connection: ClientConnection, status, text, end):
        self.event_bus.publish('background_message', {
            'client_id': connection.info.get('id'),
            'status': status,
            'text': text,
            'eof': end,
            'time': datetime.now().isoformat()
        })

    # ------------------ web task helpers ------------------ #
    def _publish_web_task_result(self, task_id: str, client_id: str, command: str, status: int, text: str):
        """
        发布 Web 任务执行中的单条结果，并写入任务记录
        """
        self.task_store.append_chunk(task_id, status, text)

        self.event_bus.publish('command_result', {
            'task_id': task_id,
            'client_id': client_id,
            'command': command,
            'status': status,
            'text': text,
            'time': datetime.now().isoformat()
        })

    def _publish_web_task_complete(self, task_id: str, client_id: str, command: str, ok: bool):
        """
        发布 Web 任务完成事件
        """
        self.event_bus.publish('command_complete', {
            'task_id': task_id,
            'client_id': client_id,
            'command': command,
            'success': ok,
            'time': datetime.now().isoformat()
        })

    def _run_web_task_stream(self, conn: ClientConnection, task_id: str, command: str, result_iter):
        """
        统一执行 Web 任务结果流：
        - 消费生成器输出
        - 记录任务分片
        - 推送 SSE 结果
        - 统一异常处理
        - 统一结束收尾
        """
        client_id = conn.info.get('id')
        ok = True

        try:
            for status, result in result_iter:
                text = '' if result is None else str(result)
                self._publish_web_task_result(task_id, client_id, command, status, text)

                if status == 0:
                    ok = False

        except Exception as e:
            ok = False
            text = str(e)
            self._publish_web_task_result(task_id, client_id, command, 0, text)

        finally:
            self.task_store.finish_task(task_id, ok)
            self._publish_web_task_complete(task_id, client_id, command, ok)

    # ------------------ web command / upload ------------------ #
    def submit_command(self, client_id: str, command: str):
        conn = self.server.get_target_connection_by_client_id(client_id)
        task = self.task_store.create_task(client_id, command)

        threading.Thread(
            target=self._run_command,
            args=(conn, task['task_id'], command),
            daemon=True
        ).start()

        return {
            'task_id': task['task_id'],
            'client_id': client_id,
            'command': command
        }

    def _run_command(self, conn: ClientConnection, task_id: str, command: str):
        def _result_iter():
            executor = CommandExecutor(conn, self.server)
            func = executor.process_command(command)
            if not func:
                raise RuntimeError('Unable to resolve command')
            yield from func()

        self._run_web_task_stream(conn, task_id, command, _result_iter())

    def submit_upload(self, client_id: str, local_path: str, display_name: str):
        conn = self.server.get_target_connection_by_client_id(client_id)
        command = f'upload {display_name}'
        task = self.task_store.create_task(client_id, command)

        threading.Thread(
            target=self._run_upload,
            args=(conn, task['task_id'], local_path, display_name),
            daemon=True
        ).start()

        return {
            'task_id': task['task_id'],
            'client_id': client_id,
            'command': command
        }

    def _run_upload(self, conn: ClientConnection, task_id: str, local_path: str, display_name: str):
        command = f'upload {display_name}'

        try:
            self._run_web_task_stream(
                conn,
                task_id,
                command,
                conn.send_file(local_path)
            )
        finally:
            try:
                if os.path.exists(local_path):
                    os.remove(local_path)
                parent_dir = os.path.dirname(local_path)
                if parent_dir.startswith(self.file_service.upload_tmp_dir) and os.path.isdir(parent_dir):
                    shutil.rmtree(parent_dir, ignore_errors=True)
            except Exception:
                pass