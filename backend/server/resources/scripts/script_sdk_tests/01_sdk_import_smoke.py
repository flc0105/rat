"""
Script SDK 基础 import 冒烟测试。

使用方式：
1. 放到 server script / pyexec_collect 中执行。
2. 这个脚本只测试 SDK 能否导入、shell 前台执行是否可用，不依赖 artifact/keychains 数据。
"""

from client.runtime.sdk import artifact, command, keychains
from client.runtime.sdk.command import BackgroundProcess, ClientCommandResult, ShellResult
from client.runtime.sdk.context import get_client_id, get_command_id, get_script_context


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    print('=== Script SDK import smoke test ===')

    print('artifact module =', artifact.__name__)
    print('command module =', command.__name__)
    print('keychains module =', keychains.__name__)

    assert_true(hasattr(artifact, 'save'), 'artifact.save missing')
    assert_true(hasattr(artifact, 'download'), 'artifact.download missing')
    assert_true(hasattr(command, 'run_shell'), 'command.run_shell missing')
    assert_true(hasattr(command, 'run_client'), 'command.run_client missing')
    assert_true(hasattr(keychains, 'get_secret'), 'keychains.get_secret missing')

    print('client_id =', get_client_id() or '<empty/outside-script-context>')
    print('command_id =', get_command_id() or '<empty/outside-script-context>')
    print('script_context keys =', sorted(get_script_context().keys()))

    result = command.run_shell('echo script-sdk-ok')
    print('shell returncode =', result.returncode)
    print('shell stdout =', result.stdout.strip())
    print('shell stderr =', result.stderr.strip())

    assert_true(isinstance(result, ShellResult), 'run_shell should return ShellResult')
    assert_true(result.ok, 'run_shell echo failed')
    assert_true('script-sdk-ok' in result.stdout, 'unexpected shell stdout')

    # 这里只验证类型可以被正常导入，后续脚本会覆盖 background/client command。
    print('imported result classes =', ShellResult.__name__, BackgroundProcess.__name__, ClientCommandResult.__name__)
    print('PASS')


if __name__ == '__main__':
    main()
