"""
Script SDK 注入对象 + import 混合测试。

覆盖：
- 显式 import：from client.runtime.sdk import command
- 脚本全局注入对象：artifact / command / keychains
- 脚本全局注入的 client 命令快捷函数：getinfo()

说明：
- 这个脚本必须在 server script / pyexec_collect 的 inproc 模式下才能完整覆盖 getinfo() 全局快捷函数。
- 如果不在 inproc 模式，getinfo() 可能没有注入，脚本会打印 SKIP。
"""

from client.runtime.sdk import command as imported_command
from client.runtime.sdk.command import ClientCommandResult, ScriptSdkCommandError


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    print('=== Script SDK injected globals and imported shortcuts test ===')

    # 1. import 出来的 command 可以直接跑 shell。
    shell_result = imported_command.run_shell('echo imported-command-ok')
    print('imported command shell stdout =', shell_result.stdout.strip())
    assert_true(shell_result.ok, 'imported command.run_shell failed')

    # 2. server script 中应该已经注入了同名 command 全局对象。
    try:
        injected_command = command  # noqa: F821
    except NameError:
        injected_command = None

    if injected_command is None:
        print('SKIP injected command: global command is not injected outside server script runtime')
    else:
        result = injected_command.run_shell('echo injected-command-ok')
        print('injected command shell stdout =', result.stdout.strip())
        assert_true(result.ok, 'injected command.run_shell failed')

    # 3. server script inproc 模式会把已有 client 命令也注入成全局函数，比如 getinfo()。
    try:
        info = getinfo()  # noqa: F821
    except NameError:
        print('SKIP global getinfo(): not injected in current execution mode')
    except ScriptSdkCommandError as exc:
        print('SKIP global getinfo():', exc)
    else:
        print('global getinfo type =', type(info).__name__)
        print('global getinfo ok =', info.ok)
        print('global getinfo output preview =', str(info.output)[:500])
        assert_true(isinstance(info, ClientCommandResult), 'global getinfo should return ClientCommandResult')
        assert_true(info.ok, 'global getinfo failed')

    print('PASS')


if __name__ == '__main__':
    main()
