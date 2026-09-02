from client.config.runtime_config import HTTP_TRANSFER_MODE


class HttpTransferStrategy:
    MODE_NAME = 'base'

    def __init__(self, owner):
        self.owner = owner

    def get_mode_name(self) -> str:
        return self.MODE_NAME

    def is_cancel_supported(self) -> bool:
        return False

    def configure_context_for_upload(self):
        self.owner._set_cancel_policy(
            supported=self.is_cancel_supported(),
            message='Current HTTP transfer mode is legacy; upload cancellation is not supported',
        )

    def configure_context_for_download(self):
        self.owner._set_cancel_policy(
            supported=self.is_cancel_supported(),
            message='Current HTTP transfer mode is legacy; download cancellation is not supported',
        )

    def resolve_http_timeout(self, fallback_timeout=None):
        timeout_value = self.owner._resolve_timeout(fallback_timeout)
        if timeout_value is None:
            return None
        return max(float(timeout_value), 0.001)

    def upload_file(self, file_path: str, upload_url: str, form_data: dict, progress_callback=None):
        raise NotImplementedError

    def download_file(self, url: str, target_path: str, progress_callback=None):
        raise NotImplementedError


def normalize_http_transfer_mode(mode: str = '') -> str:
    normalized = str(mode or '').strip().lower()
    if normalized in ('legacy', 'cancelable'):
        return normalized
    normalized_default = str(HTTP_TRANSFER_MODE or '').strip().lower()
    if normalized_default in ('legacy', 'cancelable'):
        return normalized_default
    return 'cancelable'