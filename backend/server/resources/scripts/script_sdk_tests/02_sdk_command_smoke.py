"""
Script SDK command 测试。

覆盖：
- from client.runtime.sdk import command
- command.run_shell 前台等待结果
- command.run_shell background=True 后台启动
- command.run_client('getinfo') 调用 client 已有命令
- command.getinfo() 动态快捷方法

说明：
- run_client / command.getinfo() 需要 inproc Python 执行模式，因为它要复用当前 client 命令实例。
- 如果你在 subprocess_pipe 模式跑，这两项会打印 SKIP，不算失败。
"""

import os
import sys
import tempfile

from client.runtime.sdk import command
from client.runtime.sdk.command import BackgroundProcess, ShellResult, ScriptSdkCommandError


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def make_python_cmd(code):
    # Windows / macOS / Linux 都可用的 Python 命令格式。
    return f'"{sys.executable}" -c "{code}"'


def test_run_shell_foreground():
    print('\n--- test_run_shell_foreground ---')
    result = command.run_shell(make_python_cmd("print('foreground-ok')"))
    print('result =', result)
    print('returncode =', result.returncode)
    print('stdout =', result.stdout.strip())
    print('stderr =', result.stderr.strip())

    assert_true(isinstance(result, ShellResult), 'run_shell should return ShellResult')
    assert_true(result.ok, 'foreground shell command failed')
    assert_true('foreground-ok' in result.stdout, 'foreground stdout mismatch')


def test_run_shell_background():
    print('\n--- test_run_shell_background ---')
    script_path = os.path.join(tempfile.gettempdir(), 'script_sdk_background_probe.py')
    with open(script_path, 'w', encoding='utf-8') as f:
        f.write('import time\ntime.sleep(3)\n')

    proc = command.run_shell(f'"{sys.executable}" "{script_path}"', background=True)
    print('background proc =', proc)
    print('background pid =', proc.pid)

    assert_true(isinstance(proc, BackgroundProcess), 'background run_shell should return BackgroundProcess')
    assert_true(proc.pid > 0, 'background pid should be greater than 0')


def test_run_client_getinfo():
    print('\n--- test_run_client_getinfo ---')
    try:
        info = command.run_client('getinfo')
    except ScriptSdkCommandError as exc:
        print('SKIP: command.run_client requires inproc mode or exported getinfo command:', exc)
        return

    print('getinfo ok =', info.ok)
    print('getinfo status =', info.status)
    print('getinfo output preview =', str(info.output)[:500])
    assert_true(info.ok, 'command.run_client("getinfo") failed')


def test_dynamic_shortcut_getinfo():
    print('\n--- test_dynamic_shortcut_getinfo ---')
    try:
        info = command.getinfo()
    except ScriptSdkCommandError as exc:
        print('SKIP: command.getinfo() requires inproc mode or exported getinfo command:', exc)
        return

    print('command.getinfo ok =', info.ok)
    print('command.getinfo output preview =', str(info.output)[:500])
    assert_true(info.ok, 'command.getinfo() failed')


def main():
    print('=== Script SDK command smoke test ===')
    test_run_shell_foreground()
    test_run_shell_background()
    test_run_client_getinfo()
    test_dynamic_shortcut_getinfo()
    print('\nPASS')


if __name__ == '__main__':
    main()
