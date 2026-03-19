import inspect


def argument_command(name: str):
    """
    标记一个 acmd 实验命令处理方法
    """
    def decorator(func):
        func.argument_command_name = name
        return func
    return decorator


class ArgumentCommandRegistry:
    """
    acmd 实验命令注册表。

    职责：
    - 扫描命令对象上的实验命令处理器
    - 根据 payload 中的 name 路由到对应方法
    - 统一处理参数调用形式
    """

    def __init__(self, commands):
        self.commands = commands
        self._handlers = self._collect_handlers()

    def _collect_handlers(self) -> dict:
        """
        扫描并收集所有已注册的实验命令处理器
        """
        handlers = {}

        for _, method in inspect.getmembers(
            self.commands,
            lambda x: inspect.ismethod(x) or inspect.isfunction(x)
        ):
            command_name = getattr(method, 'argument_command_name', '')
            if command_name:
                handlers[command_name] = method

        return handlers

    def has_command(self, name: str) -> bool:
        """
        判断是否存在指定实验命令
        """
        return name in self._handlers

    def execute(self, payload: dict):
        """
        执行实验命令
        payload 结构：
        {
            'name': 'msgbox',
            'args': {'title': 'aaa', 'text': 'bbb'},
            'raw': 'acmd msgbox --title aaa --text bbb'
        }
        """
        if not isinstance(payload, dict):
            return 0, 'Invalid acmd payload'

        command_name = (payload.get('name') or '').strip()
        args_dict = payload.get('args') or {}

        if not command_name:
            return 0, 'Missing acmd command name'

        if not isinstance(args_dict, dict):
            return 0, 'Invalid acmd args payload'

        handler = self._handlers.get(command_name)
        if handler is None:
            return 0, f'acmd command not supported on this platform: {command_name}'

        try:
            parameters_count = len(inspect.signature(handler).parameters)

            if parameters_count >= 2:
                return handler(args_dict, payload)

            return handler(args_dict)
        except Exception as e:
            return 0, f'acmd execution failed: {e}'