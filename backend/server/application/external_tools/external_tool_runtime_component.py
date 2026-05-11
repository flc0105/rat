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
    def install_root_dir(self) -> str:
        return self.core.install_root_dir

    @property
    def runtime_root_dir(self) -> str:
        return self.core.runtime_root_dir

    @property
    def DEFAULT_STOP_TIMEOUT_SEC(self) -> int:
        return self.core.DEFAULT_STOP_TIMEOUT_SEC

    @property
    def DEFAULT_LOG_TAIL_BYTES(self) -> int:
        return self.core.DEFAULT_LOG_TAIL_BYTES

    def __getattr__(self, name):
        return getattr(self.core, name)
