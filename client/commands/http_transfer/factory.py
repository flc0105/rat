from client.commands.http_transfer.base import normalize_http_transfer_mode
from client.commands.http_transfer.cancelable import CancelableHttpTransferStrategy
from client.commands.http_transfer.legacy import LegacyHttpTransferStrategy


def build_http_transfer_strategy(owner, mode: str = ''):
    normalized = normalize_http_transfer_mode(mode)
    if normalized == 'legacy':
        return LegacyHttpTransferStrategy(owner)
    return CancelableHttpTransferStrategy(owner)



