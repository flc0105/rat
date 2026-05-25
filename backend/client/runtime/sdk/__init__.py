"""
Server Script SDK。

脚本内可直接使用注入对象：
    artifact.save('/tmp/a.log')
    artifact.download('tool.zip', type='server_files')
    result = command.run_shell('whoami')
    info = getinfo()
    token = keychains.get_secret('token').getvalue()

也可以显式导入：
    from client.runtime.sdk import artifact, command, keychains
"""

from client.runtime.sdk import artifact, command, keychains

__all__ = ['artifact', 'command', 'keychains']
