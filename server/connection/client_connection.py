import ntpath
import os
import time
from typing import Generator

from server.config.config import BACKGROUND_MESSAGE_OUTPUT_TO_FILE, SHOW_MESSAGES_FROM_OTHER_CONNECTIONS
from core.protocol.ratsocket import RATSocket
from core.utils.common_util import get_output_stream, get_input_stream, get_readable_time
from core.utils.logger import logger, get_file_logger
from core.utils.server_util import calculate_time_interval
from core.protocol.message_queue import MessageQueue

if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
    file_logger = get_file_logger('background_messages.log')


class ClientConnection(RATSocket):

    def __init__(self, s, address=None, info=None):
        """
        初始化客户端连接

        参数:
            socket: 客户端socket对象
            address: 客户端地址(IP, 端口)元组
            info: 客户端信息字典
        """
        super().__init__()
        self.socket = s  # 客户端套接字
        self.address = address  # 客户端地址
        self.info = info  # 客户端信息

        self._pending_commands = MessageQueue()   # 等待响应的命令队列
        self._results_queue = MessageQueue()  # 未读结果/消息队列
        self._is_interactive = False  # 是否处于交互会话中
        self.command_history = [] # 命令执行历史记录

    def send_command(self, command: str, type='command', extra=None) -> Generator:
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

        return self.wait_for_result(data.get('id'), command if type == 'command' else None)

    def send_file(self, filename: str) -> Generator:
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
        if self._results_queue.get_status():  # 如果对方就绪
            self.send_io(io)  # 发送文件
        return self.wait_for_result(data.get('id'), 'upload ' + filename)

    def recv_result(self):
        """
        从客户端接收结果（子线程接收到消息后，放入该连接的队列中）
        """
        data = self.recv()  # 接收消息
        # print(data)
        type = data.get('type')  # 获取消息类型
        # 如果是就绪信号
        if type == 'rdy':
            self._results_queue.put_status(data.get('status'))  # 将就绪状态写入队列
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

        pending_command_id = self._pending_commands.peek()

        is_expected_command = (command_id == pending_command_id)

        # 预期命令始终直接输出到队列
        if is_expected_command:
            self._results_queue.put(status, text, end)
            return

        # 非预期命令的处理逻辑
        if self._is_interactive:
            # 交互模式下非预期命令
            if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
                file_logger.info(f'Message from {self.address}: {text}')
            else:
                logger.info(text)
        else:
            # 非交互模式下非预期命令

            # 非交互模式只要开启了后台消息就一定会写到文件中，不管开不开启SHOW_MESSAGES_FROM_OTHER_CONNECTIONS
            if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
                file_logger.info(f'Message from {self.address}: {text}')
                return

            # 如果没有开启后台消息且开启了不管开不开启SHOW_MESSAGES_FROM_OTHER_CONNECTIONS
            if SHOW_MESSAGES_FROM_OTHER_CONNECTIONS:
                logger.info(f'Message from {self.address}: {text}')
            else: #如果没有开启后台消息且没有开启SHOW_MESSAGES_FROM_OTHER_CONNECTIONS
                self._results_queue.put(status, text, end)

    def wait_for_result(self, id: int, command: str):
        """
        主线程等待接收结果，并保存执行记录
        :param id: 命令id
        :param command: 命令文本
        :return: 结果生成器
        """
        self._pending_commands.put_command_id(id)  # 将命令id加入待执行队列
        start_time = time.time()

        history_result = []  # 存放结果

        while 1:
            status, result, eof = self._results_queue.get()  # 获取结果
            yield status, result  # 返回状态和结果
            history_result.append(result)  # 添加到结果列表
            if eof:  # 判断是否结束
                self._pending_commands.get()  # 从待执行队列移除
                break

        end_time = time.time()
        if command:
            self.command_history.append({
                'id': id,
                'command': command,
                'time': get_readable_time(),
                'exec_time': f'{calculate_time_interval(start_time, end_time):.2f} ms',
                'status': status,
                'result': '\n'.join(history_result),
            })
