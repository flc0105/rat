from client.commands.argument_command_registry import argument_command
from client.commands.common import CommonCommands
from client.commands.interrupts import interruptible
from client.commands.specs.network import NETSTAT_ARGUMENT_SPEC


class LinuxCommands(CommonCommands):

    def __init__(self, socket):
        super().__init__(socket)

    @argument_command('netstat', spec=NETSTAT_ARGUMENT_SPEC)
    @interruptible()
    def _acmd_netstat(self, args_dict, payload=None):
        return self._acmd_netstat_common(args_dict, payload)