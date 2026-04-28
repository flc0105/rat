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
            列出 runtime_config 下所有可配置项和值，并标注 default / override 来源

        set KEY value
            修改 runtime_config.KEY。
            如果 value 和 runtime_config.py 默认值相同，则删除 JSON override。
            如果 value 和默认值不同，则写入外部 runtime_config.json。

        set --reset KEY
            删除指定 KEY 的 override，恢复 runtime_config.py 默认值

        set --reset-all
            删除所有 override，全部恢复 runtime_config.py 默认值
        """
        text = str(arg or '').strip()
        if not text:
            return 1, self._format_runtime_config_listing()

        try:
            parts = shlex.split(text)
        except Exception as e:
            return 0, f'Invalid set arguments: {e}'

        if not parts:
            return 1, self._format_runtime_config_listing()

        if parts[0] in ('--reset', 'reset', '--unset', 'unset'):
            if len(parts) != 2:
                return 0, 'Usage: set --reset KEY'
            return self._reset_runtime_config_key(parts[1])

        if parts[0] in ('--reset-all', 'reset-all', '--unset-all', 'unset-all'):
            return self._reset_all_runtime_config_overrides()

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
                f'Default: {self.runtime_config_service.format_value(result.default_value)}\n'
                f'Source: {result.source}\n'
                f'Runtime config store: {result.store_path}'
            )

            if result.override_removed:
                message += '\nOverride: removed because value equals runtime_config.py default'
            else:
                message += '\nOverride: stored because value differs from runtime_config.py default'

            if side_effects:
                message += '\n' + '\n'.join(side_effects)

            return 1, message
        except Exception as e:
            return 0, f'Failed to set runtime config: {e}'

    def _format_runtime_config_listing(self):
        removed = self.runtime_config_service.prune_redundant_overrides()
        store_path = self.runtime_config_service.get_store_path()
        active_overrides = self.runtime_config_service.format_active_overrides()
        config_items = self.runtime_config_service.format_config_items()

        message = (
            f'Runtime config store path: {store_path}\n'
            f'{active_overrides}\n'
        )

        if removed:
            message += (
                'Pruned redundant overrides: '
                + ', '.join(removed)
                + '\n'
            )

        message += '\n' + config_items
        return message

    def _reset_runtime_config_key(self, key: str):
        try:
            result = self.runtime_config_service.reset_config_key(key)
            side_effects = self._apply_runtime_config_side_effects(result.key, result.new_value)

            message = (
                f'{result.key} reset to runtime_config.py default\n'
                f'Old: {self.runtime_config_service.format_value(result.old_value)}\n'
                f'New: {self.runtime_config_service.format_value(result.new_value)}\n'
                f'Runtime config store: {result.store_path}'
            )

            if side_effects:
                message += '\n' + '\n'.join(side_effects)

            return 1, message
        except Exception as e:
            return 0, f'Failed to reset runtime config: {e}'

    def _reset_all_runtime_config_overrides(self):
        try:
            store_path = self.runtime_config_service.reset_all_overrides()
            side_effects = []

            for key, value, _, _ in self.runtime_config_service.list_config_items():
                side_effects.extend(self._apply_runtime_config_side_effects(key, value))

            message = (
                'All runtime config overrides reset to runtime_config.py defaults\n'
                f'Runtime config store: {store_path}'
            )

            if side_effects:
                deduped = []
                for item in side_effects:
                    if item not in deduped:
                        deduped.append(item)
                message += '\n' + '\n'.join(deduped)

            return 1, message
        except Exception as e:
            return 0, f'Failed to reset all runtime config overrides: {e}'

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