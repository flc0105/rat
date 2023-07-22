import ntpath
import os
import time

from client.config.config import BACKGROUND_MESSAGE_OUTPUT_TO_FILE
from common.ratsocket import RATSocket
from common.util import get_output_stream, get_input_stream, get_readable_time, logger, file_logger
from server.wrapper.message_queue import MessageQueue


class Client(RATSocket):

    def __init__(self, s, address=None, info=None):
        super().__init__()
        self.socket = s  # 客户端套接字
        self.address = address  # 客户端地址
        self.info = info  # 客户端信息
        self.commands = MessageQueue()  # 存放待执行命令
        self.results = MessageQueue()  # 存放未读消息
        self.status = False  # 是否正在交互
        self.history = {}  # 存放历史记录

    def send_command(self, command: str, type='command', extra=None):
        """
        向客户端发送命令
        :param command: 命令
        :param type: 命令类型
        :param extra: 额外信息
        :return: 结果生成器
        """
        data = {
            'type': type,
            'id': int(time.time()),
            'text': command,
        }
        if extra:
            data['extra'] = extra
        self.send(data)
        return self.wait_for_result(data.get('id'), command)

    def send_file(self, filename: str):
        """
        向客户端发送文件
        :param filename: 文件名
        :return: 结果生成器
        """
        data = {
            'type': 'file',
            'id': int(time.time()),
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
        }
        io = get_output_stream(filename)
        self.send(data)  # 发送文件请求头
        if self.results.get_status():  # 如果对方就绪
            self.send_io(io)  # 发送文件
        return self.wait_for_result(data.get('id'), 'upload ' + filename)

    def recv_result(self):
        """
        从客户端接收结果（子线程接收到消息后，放入该连接的队列中）
        """
        data = self.recv()  # 接收消息
        type = data.get('type')  # 获取消息类型
        # 如果是就绪信号
        if type == 'rdy':
            self.results.put_status(data.get('status'))  # 将就绪状态写入队列
            return
        self.info['cwd'] = data.get('cwd')  # 更新工作路径
        result_id = data.get('id')  # 结果id
        # 如果是命令执行结果
        if type == 'result':
            self.handle_result(result_id, data.get('status'), data.get('text'), data.get('eof'))
        # 如果是文件
        elif type == 'file':
            self.handle_result(result_id, *self.save_file(data.get('filename'), data.get('length')), 1)

    def save_file(self, filename, len):
        """
        保存文件
        :param filename: 文件名
        :param length: 文件长度
        :return: 文件保存结果元组 (status, message)
        """
        file = os.path.abspath(filename)
        try:
            io = get_input_stream(file)
            try:
                self.send_signal(1)
                self.recv_io(len, io)
                return 1, f'File saved to: {file}'
            except Exception as e:
                return 0, f'Error receiving file from {self.address}: {e}'
        except Exception as e:
            self.send_signal(0)
            return 0, f'Error opening local file: {e}'

    def handle_result(self, command_id, status, text, end):
        """
        处理结果
        :param command_id: 命令id
        :param status: 状态
        :param text: 结果文本
        :param end: 是否结束
        """
        pending_command_id = self.commands.peek()
        if self.status:  # 如果当前正在交互
            if command_id == pending_command_id:  # 是在等待执行的命令
                self.results.put(status, text, end)  # 结果放入队列
                return
        if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
            file_logger.info(text)
        else:
            logger.info(text)
        # logger.info(text)  # 其他信息展示

    def wait_for_result(self, id: int, command: str):
        """
        主线程等待接收结果
        :param id: 命令id
        :param command: 命令文本
        :return: 结果生成器
        """
        self.commands.put_command(id)  # 将命令id加入待执行队列

        history_result = []  # 存放结果

        while 1:
            status, result, eof = self.results.get()  # 获取结果
            yield status, result  # 返回状态和结果
            history_result.append(result)  # 添加到结果列表
            if eof:  # 判断是否结束
                self.commands.get()  # 从待执行队列移除
                break

        self.history[id] = {  # 保存到历史记录
            'command': command,
            'timestamp': get_readable_time(),
            'status': status,
            'result': '\n'.join(history_result),
        }
