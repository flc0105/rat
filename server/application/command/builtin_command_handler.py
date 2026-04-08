from server.application.command.builtin_command_support import (
    AliasBuiltinSupport,
    HistoryBuiltinSupport,
    RttBuiltinSupport,
    ScriptBuiltinSupport,
    UploadBuiltinSupport,
)


class BuiltinCommandHandler:
    """
    内建命令处理器。

    职责：
    - 提供内建命令候选项
    - 分发 upload / exec / alias / unalias / history / rtt 等内建命令
    - 不负责命令总路由，也不直接决定 alias / default / acmd 的分流
    """

    WEB_COMMAND_TEMPLATES = [
        {
            'name': 'upload',
            'template': 'upload ',
            'help': 'upload <local_file> | Upload a local file to the client',
            'source': 'server'
        },
        {
            'name': 'exec',
            'template': 'exec ',
            'help': 'exec <script.py> | Execute a server-side Python script on the client',
            'source': 'server'
        },
        {
            'name': 'alias',
            'template': 'alias ',
            'help': 'alias [--platform win|mac|common] <name> = <command> | Save a command alias',
            'source': 'server'
        },
        {
            'name': 'unalias',
            'template': 'unalias ',
            'help': 'unalias [--platform win|mac|common] <name> | Remove a command alias',
            'source': 'server'
        },
        {
            'name': 'history',
            'template': 'history',
            'help': 'Show de-duplicated command history for the current host. Use history run <index> or !<index> to run an item quickly',
            'source': 'server'
        },
        {
            'name': 'history',
            'template': 'history run ',
            'help': 'history run <index> | Run an item from quick history by index',
            'source': 'server'
        },
        {
            'name': 'history',
            'template': 'history clear',
            'help': 'Clear command history for the current host',
            'source': 'server'
        },
        {
            'name': 'rtt',
            'template': 'rtt',
            'help': 'Show current heartbeat RTT / last seen state',
            'source': 'server'
        },
    ]

    def __init__(
        self,
        conn,
        server,
        plan_builder,
        remote_execution_service,
        history_entry_id_provider,
        plan_executor_factory,
        command_processor_factory,
    ):
        self.conn = conn
        self.server = server
        self.plan_builder = plan_builder
        self.remote_execution_service = remote_execution_service
        self.history_entry_id_provider = history_entry_id_provider
        self.plan_executor_factory = plan_executor_factory
        self.command_processor_factory = command_processor_factory

        self.upload_support = UploadBuiltinSupport(
            conn=self.conn,
            remote_execution_service=self.remote_execution_service,
            history_entry_id_provider=self.history_entry_id_provider,
        )
        self.script_support = ScriptBuiltinSupport(
            plan_builder=self.plan_builder,
            plan_executor_factory=self.plan_executor_factory,
        )
        self.alias_support = AliasBuiltinSupport(
            alias_manager=self.server.alias_manager,
            conn=self.conn,
        )
        self.history_support = HistoryBuiltinSupport(
            command_history=self.server.command_history,
            conn=self.conn,
            history_entry_id_provider=self.history_entry_id_provider,
            command_processor_factory=self.command_processor_factory,
        )
        self.rtt_support = RttBuiltinSupport(
            conn=self.conn,
        )

    def get_command_candidates(self):
        candidates = [dict(item) for item in self.WEB_COMMAND_TEMPLATES]

        for script in self.script_support.list_scripts():
            candidates.append({
                'name': 'exec',
                'template': f'exec {script}',
                'help': f'Execute script: {script}',
                'source': 'script'
            })

        for alias_name, alias_command in self.alias_support.list_aliases().items():
            candidates.append({
                'name': alias_name,
                'template': alias_name,
                'help': f'Alias -> {alias_command}',
                'source': 'alias'
            })

        return candidates

    def resolve_builtin_command(self, name, arg):
        if not hasattr(self, name):
            return None

        handler = getattr(self, name)
        if not callable(handler):
            return None

        return handler(arg)

    def upload(self, filename):
        for item in self.upload_support.upload(filename):
            yield item

    def exec(self, filename):
        if not filename:
            yield 1, '\n'.join(self.script_support.list_scripts())
            return

        for item in self.script_support.execute_script_file(filename):
            yield item

    def alias(self, arg):
        for item in self.alias_support.alias(arg):
            yield item

    def unalias(self, arg):
        for item in self.alias_support.unalias(arg):
            yield item

    def history(self, arg):
        for item in self.history_support.history(arg):
            yield item

    def rtt(self, arg=''):
        for item in self.rtt_support.rtt(arg):
            yield item
