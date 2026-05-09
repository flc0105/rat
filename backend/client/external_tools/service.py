from client.external_tools.cache import ExternalToolCache
from client.external_tools.daemon_instance import ExternalToolDaemonInstance
from client.external_tools.exec_tool import ExternalToolCliExec
from client.external_tools.installer import ExternalToolInstaller
from client.external_tools.oneshot import ExternalToolOneshot


class ExternalToolClientService(
    ExternalToolDaemonInstance,
    ExternalToolOneshot,
    ExternalToolInstaller,
    ExternalToolCliExec,
    ExternalToolCache,
):
    """
    Client-side external tool lifecycle facade.

    Business areas are split by external tool usage mode:
    - daemon instance lifecycle
    - oneshot execution
    - installer / uninstall / install status
    - CLI-facing exec / which
    - package cache
    """

    def __init__(self, command_host):
        self.command_host = command_host
