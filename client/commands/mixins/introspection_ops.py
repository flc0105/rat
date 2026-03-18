import inspect

from core.utils.decorator import desc
from core.utils.formatting import format_dict


class CommandIntrospectionMixin:
    def _get_exported_command_methods(self):
        """
        获取所有可导出的命令方法
        """
        return {
            name: method
            for name, method in inspect.getmembers(
                self,
                lambda x: inspect.isfunction(x) or inspect.ismethod(x)
            )
            if hasattr(method, 'help')
        }

    def get_command_manifest_payload(self):
        """
        获取命令清单数据（本地方法，不通过 socket 返回）
        """
        methods = self._get_exported_command_methods()
        payload = [
            {
                'name': name,
                'help': method.help,
            }
            for name, method in methods.items()
        ]
        payload.sort(key=lambda item: item['name'].lower())
        return payload

    @desc('Show available commands')
    def help(self):
        methods = self._get_exported_command_methods()
        return 1, format_dict({name: method.help for name, method in methods.items()})