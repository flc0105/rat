"""
命令运行时与 HTTP 传输相关配置。

说明：
- 不改动原有 client.config.config
- 将 timeout / HTTP 传输模式等新能力集中到这里
- HTTP_TRANSFER_MODE:
  - legacy: 保留原版 requests files=... / iter_content() 行为，不支持取消
  - cancelable: 使用可取消 / 可超时的流式实现
- 本文件只提供默认值；运行时 set 命令写入外部 runtime_config.json 覆盖文件，不修改本源码文件
"""

# ------------------ command runtime ------------------ #
# 通用命令兜底超时：只在命令没有更具体的 fallback timeout 时生效。
# 不覆盖 shell / stream / HTTP 等命令自己的专用 timeout。
COMMAND_DEFAULT_TIMEOUT = None
COMMAND_DEFAULT_SHELL_TIMEOUT = 30
COMMAND_DEFAULT_STREAM_TIMEOUT = 300

# ------------------ http transfer strategy ------------------ #
# HTTP_TRANSFER_MODE = 'cancelable'
HTTP_TRANSFER_MODE = 'legacy'

# ------------------ http upload ------------------ #
HTTP_UPLOAD_TIMEOUT = 120

# ------------------ http download ------------------ #
HTTP_DOWNLOAD_CONNECT_TIMEOUT = 15
HTTP_DOWNLOAD_READ_TIMEOUT = 300

# ------------------ preview image compression ------------------ #
# 只影响 preview_path 的 web 预览上传，不影响 download_path / 平台命令 / script 上传。
PREVIEW_IMAGE_COMPRESS_ENABLED = False
PREVIEW_IMAGE_COMPRESS_QUALITY = 75

# PYTHON_EXECUTION_MODE = 'subprocess_pipe'
PYTHON_EXECUTION_MODE = 'inproc'


RECONNECT_INTERVAL_SECONDS = 5
REMOTE_HTTP_WATCHDOG_ENABLED = False
REMOTE_HTTP_WATCHDOG_INTERVAL_SECONDS = 15
LOCAL_WATCHDOG_ENABLED = False
LOCAL_WATCHDOG_HEARTBEAT_INTERVAL_SECONDS = 5
LOCAL_WATCHDOG_TIMEOUT_SECONDS = 15


# runtime_config 暴露元信息。
# expose=True 的配置会出现在普通 set 输出和 set 自动补全中，也允许通过 set KEY value 修改。
# expose=False 的配置保留在本文件和 set --all 输出中，但默认不允许直接 set 修改。
# 如果以后希望隐藏项也允许修改，把 RuntimeConfigService.is_supported_key() 改为调用 is_known_config_key() 即可。
_RUNTIME_CONFIG_META = {
    'COMMAND_DEFAULT_TIMEOUT': {
        'group': 'command',
        'expose': False,
        'desc': 'Default command context timeout.',
    },
    'COMMAND_DEFAULT_SHELL_TIMEOUT': {
        'group': 'command',
        'expose': True,
        'desc': 'Default timeout for shell command execution.',
    },
    'COMMAND_DEFAULT_STREAM_TIMEOUT': {
        'group': 'command',
        'expose': True,
        'desc': 'Default timeout for stream command execution.',
    },
    'HTTP_TRANSFER_MODE': {
        'group': 'strategy',
        'expose': True,
        'desc': 'HTTP transfer implementation mode: legacy or cancelable.',
    },
    'HTTP_UPLOAD_TIMEOUT': {
        'group': 'upload',
        'expose': False,
        'desc': 'HTTP upload timeout in seconds.',
    },
    'HTTP_DOWNLOAD_CONNECT_TIMEOUT': {
        'group': 'download',
        'expose': False,
        'desc': 'HTTP download connect timeout in seconds.',
    },
    'HTTP_DOWNLOAD_READ_TIMEOUT': {
        'group': 'download',
        'expose': False,
        'desc': 'HTTP download read timeout in seconds.',
    },
    'PREVIEW_IMAGE_COMPRESS_ENABLED': {
        'group': 'preview',
        'expose': True,
        'desc': 'Enable image compression before preview upload.',
    },
    'PREVIEW_IMAGE_COMPRESS_QUALITY': {
        'group': 'preview',
        'expose': True,
        'desc': 'JPEG quality used for compressed preview images.',
    },
    'PYTHON_EXECUTION_MODE': {
        'group': 'strategy',
        'expose': True,
        'desc': 'Python script execution mode: inproc or subprocess_pipe.',
    },
    'RECONNECT_INTERVAL_SECONDS': {
        'group': 'connection',
        'expose': True,
        'desc': 'Reconnect interval after client connection loss.',
    },
    'REMOTE_HTTP_WATCHDOG_ENABLED': {
        'group': 'watchdog',
        'expose': True,
        'desc': 'Enable remote HTTP watchdog.',
    },
    'REMOTE_HTTP_WATCHDOG_INTERVAL_SECONDS': {
        'group': 'watchdog',
        'expose': False,
        'desc': 'Remote HTTP watchdog check interval in seconds.',
    },
    'LOCAL_WATCHDOG_ENABLED': {
        'group': 'watchdog',
        'expose': True,
        'desc': 'Enable local watchdog heartbeat.',
    },
    'LOCAL_WATCHDOG_HEARTBEAT_INTERVAL_SECONDS': {
        'group': 'watchdog',
        'expose': False,
        'desc': 'Local watchdog heartbeat interval in seconds.',
    },
    'LOCAL_WATCHDOG_TIMEOUT_SECONDS': {
        'group': 'watchdog',
        'expose': False,
        'desc': 'Local watchdog timeout in seconds.',
    },
}


# 记录源码默认值。set 命令会用它判断 override 是否冗余。
_RUNTIME_CONFIG_DEFAULTS = {
    _key: _value
    for _key, _value in list(globals().items())
    if _key.isupper() and isinstance(_value, (str, int, float, bool, type(None)))
}


# 外部 runtime_config.json 覆盖默认值。这里不写源码文件，兼容打包场景。
try:
    from client.config.runtime_config_store import load_runtime_overrides, get_runtime_config_path

    _RUNTIME_CONFIG_OVERRIDE_PATH = get_runtime_config_path()
    _RUNTIME_CONFIG_OVERRIDE_KEYS = []

    for _key, _value in load_runtime_overrides().items():
        if _key in globals() and _key.isupper():
            globals()[_key] = _value
            _RUNTIME_CONFIG_OVERRIDE_KEYS.append(_key)
except Exception:
    _RUNTIME_CONFIG_OVERRIDE_PATH = ''
    _RUNTIME_CONFIG_OVERRIDE_KEYS = []
finally:
    try:
        del load_runtime_overrides
    except Exception:
        pass
    try:
        del get_runtime_config_path
    except Exception:
        pass
    try:
        del _key
    except Exception:
        pass
    try:
        del _value
    except Exception:
        pass