class ExternalToolRuntimeComponent:
    """Small component base that shares the runtime core without re-inheriting the facade."""

    def __init__(self, core):
        self.core = core

    @property
    def catalog_service(self):
        return self.core.catalog_service

    @property
    def command_execution_api(self):
        return self.core.command_execution_api

    @property
    def remote_execution_service(self):
        return self.core.remote_execution_service

    @property
    def DEFAULT_LOG_TAIL_BYTES(self) -> int:
        return self.core.DEFAULT_LOG_TAIL_BYTES

    def __getattr__(self, name):
        return getattr(self.core, name)
