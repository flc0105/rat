from core.utils.decorator import desc
from core.utils.formatting import format_dict
import inspect


class CommandIntrospectionMixin:
    def _get_exported_command_methods(self, include_hidden: bool = True):
        """
        获取所有可导出的命令方法

        Args:
            include_hidden: 是否包含 hide_from_help=True 的命令
        """
        methods = {
            name: method
            for name, method in inspect.getmembers(
                self,
                lambda x: inspect.isfunction(x) or inspect.ismethod(x)
            )
            if hasattr(method, 'help')
        }

        if include_hidden:
            return methods

        return {
            name: method
            for name, method in methods.items()
            if not getattr(method, 'hide_from_help', False)
        }

    def get_command_manifest_payload(self):
        """
        获取命令清单数据（本地方法，不通过 socket 返回）
        Web 端仍可看到隐藏于 help 的命令。
        """
        methods = self._get_exported_command_methods(include_hidden=True)
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
        methods = self._get_exported_command_methods(include_hidden=False)
        return 1, format_dict({name: method.help for name, method in methods.items()})