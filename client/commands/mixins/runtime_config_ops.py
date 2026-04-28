import shlex

from client.commands.interrupts import interruptible
from client.commands.services.runtime_config_service import RuntimeConfigService
from core.utils.decorator import desc
from core.utils.logger import logger


class CommandRuntimeConfigMixin:
    """
    client runtime_config 查询与修改命令。
    """

    WATCHDOG_CONFIG_KEYS = {
        'REMOTE_HTTP_WATCHDOG_ENABLED',
        'REMOTE_HTTP_WATCHDOG_INTERVAL_SECONDS',
        'LOCAL_WATCHDOG_ENABLED',
        'LOCAL_WATCHDOG_HEARTBEAT_INTERVAL_SECONDS',
        'LOCAL_WATCHDOG_TIMEOUT_SECONDS',
    }

    @property
    def runtime_config_service(self):
        service = getattr(self, '_runtime_config_service', None)
        if service is None:
            service = RuntimeConfigService()
            self._runtime_config_service = service
        return service

    @desc('Show or update client runtime config', group='runtime')
    @interruptible()
    def set(self, arg=''):
        """
        set
            列出 runtime_config 下所有可配置项和值

        set KEY value
            修改 runtime_config.KEY，实时更新当前 client，并写入外部 runtime_config.json
        """
        text = str(arg or '').strip()

        if not text:
            config_path = self.runtime_config_service.get_store_path()
            config_items = self.runtime_config_service.format_config_items()
            return 1, (
                f'Runtime config path: {config_path}\n'
                f'{config_items}'
            )

        # if not text:
        #     return 1, self.runtime_config_service.format_config_items()

        try:
            parts = shlex.split(text)
        except Exception as e:
            return 0, f'Invalid set arguments: {e}'

        if len(parts) < 2:
            return 0, 'Usage: set KEY value'

        key = parts[0]
        value = parts[1] if len(parts) == 2 else ' '.join(parts[1:])

        try:
            result = self.runtime_config_service.set_config_value(key, value)
            side_effects = self._apply_runtime_config_side_effects(result.key, result.new_value)
            message = (
                f'{result.key} updated\n'
                f'Old: {self.runtime_config_service.format_value(result.old_value)}\n'
                f'New: {self.runtime_config_service.format_value(result.new_value)}\n'
                f'Synced: {result.store_path}'
            )
            if side_effects:
                message += '\n' + '\n'.join(side_effects)
            return 1, message
        except Exception as e:
            return 0, f'Failed to set runtime config: {e}'

    def _apply_runtime_config_side_effects(self, key: str, value):
        """
        处理少数不能只靠模块变量替换实时生效的配置。
        """
        effects = []

        if key == 'RECONNECT_INTERVAL_SECONDS':
            try:
                import ratclient
                ratclient.Client.RECONNECT_INTERVAL = value
                effects.append('Applied: Client.RECONNECT_INTERVAL updated')
            except Exception as e:
                logger.warning(f'Failed to apply reconnect interval runtime update: {e}')

        if key == 'COMMAND_DEFAULT_SHELL_TIMEOUT':
            try:
                from client.commands.mixins.execution_ops import CommandExecutionMixin
                CommandExecutionMixin.DEFAULT_SHELL_TIMEOUT = value
                effects.append('Applied: CommandExecutionMixin.DEFAULT_SHELL_TIMEOUT updated')
            except Exception as e:
                logger.warning(f'Failed to apply shell timeout runtime update: {e}')

        if key == 'COMMAND_DEFAULT_STREAM_TIMEOUT':
            try:
                from client.commands.mixins.execution_ops import CommandExecutionMixin
                CommandExecutionMixin.DEFAULT_STREAM_TIMEOUT = value
                effects.append('Applied: CommandExecutionMixin.DEFAULT_STREAM_TIMEOUT updated')
            except Exception as e:
                logger.warning(f'Failed to apply stream timeout runtime update: {e}')

        if key == 'COMMAND_PROCESS_WAIT_POLL_INTERVAL':
            try:
                from client.commands.mixins.execution_ops import CommandExecutionMixin
                CommandExecutionMixin.PROCESS_WAIT_POLL_INTERVAL = value
                effects.append('Applied: CommandExecutionMixin.PROCESS_WAIT_POLL_INTERVAL updated')
            except Exception as e:
                logger.warning(f'Failed to apply process wait poll interval runtime update: {e}')

        if key in self.WATCHDOG_CONFIG_KEYS:
            if self._restart_guard_manager():
                effects.append('Applied: watchdog runtime restarted')

        return effects

    def _restart_guard_manager(self) -> bool:
        guard_manager = getattr(self.socket, 'guard_manager', None)
        if guard_manager is None:
            return False

        try:
            guard_manager.stop()
            guard_manager.start()
            return True
        except Exception as e:
            logger.warning(f'Failed to restart watchdog runtime after config update: {e}')
            return False