from client.commands.mixins.execution_ops import CommandExecutionMixin
from client.commands.mixins.file_cli_ops import CommandFileCliMixin
from client.commands.mixins.file_web_ops import CommandFileWebMixin
from client.commands.mixins.introspection_ops import CommandIntrospectionMixin
from client.commands.mixins.job_ops import CommandJobMixin
from client.commands.mixins.process_ops import CommandProcessMixin
from client.commands.mixins.session_ops import CommandSessionMixin
from client.commands.mixins.system_ops import CommandSystemMixin
from client.commands.mixins.update_ops import CommandUpdateMixin
from client.commands.mixins.watchdog_ops import CommandWatchdogMixin


class CommonShellCommands(
    CommandExecutionMixin,
    CommandSessionMixin,
    CommandSystemMixin,
):
    """
    shell-like / session / system 通用命令组。
    """
    pass


class CommonFileCommands(
    CommandFileCliMixin,
    CommandFileWebMixin,
):
    """
    文件传输和远程文件管理命令组。
    """
    pass


class CommonRuntimeCommands(
    CommandIntrospectionMixin,
    CommandJobMixin,
    CommandProcessMixin,
    CommandWatchdogMixin,
    CommandUpdateMixin,
):
    """
    client runtime 管理类命令组。
    """
    pass