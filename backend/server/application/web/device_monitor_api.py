class WebDeviceMonitorApi:
    def __init__(self, device_monitor_session_service):
        self.device_monitor_session_service = device_monitor_session_service

    def open_monitor(self, client_id: str, tab_id: str, *, channels=None, intervals=None) -> dict:
        return self.device_monitor_session_service.create_session(
            client_id,
            tab_id,
            channels=channels,
            intervals=intervals,
        )

    def update_monitor(self, monitor_session_id: str, tab_id: str, *, channels=None, intervals=None) -> dict:
        return self.device_monitor_session_service.update_session(
            monitor_session_id,
            tab_id,
            channels=channels,
            intervals=intervals,
        )

    def close_monitor(self, monitor_session_id: str, tab_id: str) -> dict:
        return self.device_monitor_session_service.close_session(monitor_session_id, tab_id=tab_id)
