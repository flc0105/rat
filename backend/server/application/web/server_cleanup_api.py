class WebServerCleanupApi:
    """Web-facing cleanup facade."""

    def __init__(self, cleanup_service):
        self.cleanup_service = cleanup_service

    def schedule_startup_cleanup(self) -> bool:
        return self.cleanup_service.schedule_startup_cleanup()

    def get_log_path(self, run_id: str) -> str:
        return self.cleanup_service.get_log_path(run_id)
