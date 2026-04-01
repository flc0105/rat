from client.commands.base import CommandBase
from client.commands.mixins.execution_ops import CommandExecutionMixin
from client.commands.mixins.file_cli_ops import CommandFileCliMixin
from client.commands.mixins.file_web_ops import CommandFileWebMixin
from client.commands.mixins.introspection_ops import CommandIntrospectionMixin
from client.commands.mixins.job_ops import CommandJobMixin
from client.commands.mixins.path_ops import CommandPathMixin
from client.commands.mixins.process_ops import CommandProcessMixin


class CommonCommands(
    CommandExecutionMixin,
    CommandFileCliMixin,
    CommandFileWebMixin,
    CommandPathMixin,
    CommandIntrospectionMixin,
    CommandJobMixin,
    CommandBase,
    CommandProcessMixin,
):
    """跨平台通用命令集合"""
    pass


