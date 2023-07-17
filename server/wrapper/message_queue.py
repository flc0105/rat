import queue


class MessageQueue:
    def __init__(self):
        self.queue = queue.Queue()

    def get(self):
        """
        获取并删除队列中的元素
        :return: 队列中的元素
        """
        return self.queue.get()

    def get_status(self):
        """
        获取并删除队列中的元素
        :return: 队列中的元素
        """
        return self.queue.get()[0]

    def __getitem__(self, index):
        """
        获取队列中指定位置的元素，不删除
        :param index: 索引位置
        :return: 队列中的元素
        """
        return self.queue.queue[index]

    def peek(self):
        if not self.empty():
            return self.queue.queue[0]

    def put(self, status, message, end=1):
        """
        向队列中添加元素
        :param status: 状态
        :param message: 消息
        :param end: 是否结束
        """
        self.queue.put((status, message, end))

    def put_status(self, status):
        """
        向队列中添加元素
        :param status: 状态
        :param message: 消息
        :param eof: EOF标记
        """
        self.queue.put((status, None, 1))

    def put_command(self, command_id):
        """
        向队列中添加元素
        :param status: 状态
        :param message: 消息
        :param eof: EOF标记
        """
        self.queue.put(command_id)

    def empty(self):
        """
        判断队列是否为空
        :return: True 如果队列为空，否则 False
        """
        return self.queue.empty()

    def clear(self):
        """
        清空队列
        """
        with self.queue.mutex:
            self.queue.queue.clear()

    def __len__(self):
        """
        返回队列中元素的数量
        :return: 队列中元素的数量
        """
        return self.queue.qsize()
