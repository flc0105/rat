"""
命令运行时与 HTTP 传输相关配置。

说明：
- 不改动原有 client.config.config
- 将 timeout / chunk size / HTTP 传输模式等新能力集中到这里
- HTTP_TRANSFER_MODE:
  - legacy: 保留原版 requests files=... / iter_content() 行为，不支持取消
  - cancelable: 使用可取消 / 可超时的流式实现
"""

# ------------------ command runtime ------------------ #
COMMAND_DEFAULT_TIMEOUT = None
COMMAND_DEFAULT_SHELL_TIMEOUT = 30
COMMAND_DEFAULT_STREAM_TIMEOUT = 300
COMMAND_PROCESS_WAIT_POLL_INTERVAL = 0.2

# ------------------ http transfer mode ------------------ #
# HTTP_TRANSFER_MODE = 'cancelable'
HTTP_TRANSFER_MODE = 'legacy'
HTTP_TRANSFER_MODE_LEGACY = 'legacy'
HTTP_TRANSFER_MODE_CANCELABLE = 'cancelable'

# ------------------ http upload ------------------ #
HTTP_UPLOAD_TIMEOUT_LEGACY = 120
HTTP_UPLOAD_TIMEOUT_CANCELABLE = 120
HTTP_UPLOAD_CHUNK_SIZE = 128 * 1024
HTTP_UPLOAD_CANCEL_UNSUPPORTED_MESSAGE = 'Current HTTP transfer mode is legacy; upload cancellation is not supported'

# ------------------ http download ------------------ #
HTTP_DOWNLOAD_CONNECT_TIMEOUT_LEGACY = 15
HTTP_DOWNLOAD_READ_TIMEOUT_LEGACY = 300
HTTP_DOWNLOAD_CONNECT_TIMEOUT_CANCELABLE = 15
HTTP_DOWNLOAD_READ_TIMEOUT_CANCELABLE = 300
HTTP_DOWNLOAD_CHUNK_SIZE = 64 * 1024
HTTP_DOWNLOAD_CANCEL_UNSUPPORTED_MESSAGE = 'Current HTTP transfer mode is legacy; download cancellation is not supported'

# ------------------ path / zip traversal ------------------ #
ZIP_CANCEL_CHECK_INTERVAL = 64

PYTHON_EXECUTION_MODE = 'inproc'

