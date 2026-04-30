import json

from core.utils.decorator import desc


class CommandWatchdogMixin:
    @desc('Show watchdog runtime status as JSON', group='session')
    def watchdog(self, arg=''):
        guard_manager = getattr(self.socket, 'guard_manager', None)
        if guard_manager is None:
            return 0, 'Guard manager unavailable'

        try:
            payload = guard_manager.get_watchdog_status_payload()
            return 1, json.dumps(payload, ensure_ascii=False, indent=2)
        except Exception as e:
            return 0, f'Failed to get watchdog status: {e}'