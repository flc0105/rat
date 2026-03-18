from client.commands.base import CommandBase
from client.commands.mixins.execution_ops import CommandExecutionMixin
from client.commands.mixins.file_ops import CommandFileMixin
from client.commands.mixins.introspection_ops import CommandIntrospectionMixin
from client.commands.mixins.job_ops import CommandJobMixin
from client.commands.mixins.path_ops import CommandPathMixin


class CommonCommands(
    CommandExecutionMixin,
    CommandFileMixin,
    CommandPathMixin,
    CommandIntrospectionMixin,
    CommandJobMixin,
    CommandBase
):
    """跨平台通用命令集合"""
    pass