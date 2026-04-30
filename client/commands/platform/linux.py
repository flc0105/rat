from client.commands.arguments.acmd_registry import argument_command
from client.commands.common.commands import CommonCommands
from client.commands.runtime.interrupts import interruptible
from client.commands.platform.specs.common import NETSTAT_ARGUMENT_SPEC


class LinuxCommands(CommonCommands):

    def __init__(self, socket):
        super().__init__(socket)

    @argument_command('netstat', spec=NETSTAT_ARGUMENT_SPEC)
    @interruptible()
    def _acmd_netstat(self, args_dict, payload=None):
        return self._acmd_netstat_common(args_dict, payload)