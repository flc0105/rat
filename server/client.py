import json
import ntpath
import os
import uuid

from common.ratsocket import RATSocket
from common.util import get_read_stream
from server.util import update_progress


class Client(RATSocket):

    def __init__(self, s, address=None, info=None):
        super().__init__()
        self.socket = s
        self.address = address
        self.info = info
        self.id = str(uuid.uuid4())
        self.result = {}

    def send_command(self, command, type='command'):
        body = command.encode()
        head = {
            'id': str(uuid.uuid4()),
            'type': type,
            'length': len(body)
        }
        self.send(head, bytes=body)
        return head['id']

    def send_file(self, filename, id=str(uuid.uuid4()), type='file', args=None):
        head = {
            'id': id,
            'type': type,
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
            'args': json.dumps(args) if args is not None else None
        }
        self.send(head, file_stream=get_read_stream(filename),
                  update_progress=update_progress if type == 'file' else None)
