import ctypes
import inspect
import shlex
from functools import wraps

from client.util.win32util import get_integrity_level
from common.util import parse_args, format_dict, parse


def desc(text):
    """
    装饰器函数，用于为函数或方法添加帮助文档。

    Args:
        text (str): 帮助文档的内容。

    Returns:
        function: 装饰后的函数或方法对象。

    Example:
        @desc('这是一个示例函数')
        def my_function():
            pass
    """

    def attr_decorator(func):
        setattr(func, 'help', text)  # 添加帮助文档属性到函数或方法对象
        return func

    return attr_decorator


def params(*arg_list):
    """
        装饰器函数，用于将解析的参数赋值给函数的属性。

        Args:
            *arg_list: 可变长度的参数列表。

        Returns:
            function: 装饰后的函数对象。

        Example:
            @params(['param1', 'param2'])
            def my_function(self, argument_string):
                pass
        """

    def attr_decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            arg_dict = parse_args(arg_list, shlex.split(args[0]))  # 解析参数 将方法的第一个参数字符串解析为参数字典
            for key in arg_dict:
                setattr(func, key, arg_dict[key])  # 将解析的参数赋值给函数的属性
            return func(self, func, *args, **kwargs)

        wrapper.__signature__ = inspect.signature(func)  # 设置函数签名
        return wrapper

    return attr_decorator


def require_admin(func):
    """
    装饰器函数，要求以管理员权限运行函数。

    Args:
        func (function): 被装饰的函数。

    Returns:
        function: 装饰后的函数对象。

    Example:
        @require_admin
        def my_function():
            pass
    """

    def wrapper(*args):
        """
        装饰器内部函数，用于检查是否以管理员权限运行函数。

        Args:
            *args: 函数的参数列表。

        Returns:
            tuple: 如果以管理员权限运行，则返回被装饰函数的结果；否则返回(0, 'Administrator privileges required')。

        """
        if ctypes.windll.shell32.IsUserAnAdmin():
            return func(*args)
        else:
            return 0, 'Administrator privileges required'

    wrapper.__signature__ = inspect.signature(func)
    return wrapper


def require_integrity(integrity_level):
    """
    装饰器函数，要求特定完整性级别运行函数。

    Args:
        integrity_level (str): 要求的完整性级别。

    Returns:
        function: 装饰后的函数对象。

    Example:
        @require_integrity('System')
        def my_function():
            pass
    """

    def attr_decorator(func):
        @wraps(func)
        def wrapper(*args):
            """
            装饰器内部函数，用于检查完整性级别并运行函数。

            Args:
                *args: 函数的参数列表。

            Returns:
                tuple: 如果完整性级别符合要求，则返回被装饰函数的结果；否则返回(0, f'{integrity_level} integrity level required')。

            """
            if integrity_level == get_integrity_level():
                return func(*args)
            else:
                return 0, f'{integrity_level} integrity level required'

        wrapper.__signature__ = inspect.signature(func)
        return wrapper

    return attr_decorator


def enclosing(func):
    """
    封装函数装饰器，用于处理嵌套函数的调用和帮助信息获取。
    :param func: 被装饰的函数
    :return: 封装后的函数
    """

    def wrapper(*args):
        """
        封装函数的包装器，处理嵌套函数的调用和帮助信息获取。
        :param args: 函数参数
        :return: 封装后的函数的执行结果
        """
        # 获取嵌套函数字典
        nested_funcs = {k: v for k, v in func(*args).items() if callable(v)}
        # 检查装饰函数类型，获取参数字符串
        arg_str = None
        if inspect.isfunction(func):
            arg_str = args[1]
        if inspect.ismethod(func):
            arg_str = args[0]
        # 如果没有参数字符串，则返回嵌套函数的帮助信息
        if not arg_str:
            return 1, format_dict({k: v.help for k, v in nested_funcs.items() if hasattr(v, 'help')}, index=True)
        # 解析参数字符串，获取命令名和参数值
        cmd_name, cmd_arg = parse(arg_str)
        nested_func = None
        try:
            # 尝试将命令名解析为索引，获取对应的嵌套函数
            index = int(cmd_name)
            nested_func = list(nested_funcs.items())[index][1]
        except (ValueError, IndexError):
            # 如果解析失败，则检查命令名是否存在于嵌套函数字典中
            if cmd_name in nested_funcs:
                nested_func = nested_funcs[cmd_name]
        finally:
            if not nested_func:
                return 0, f'No such function: {cmd_name}'
            # 检查嵌套函数是否有参数，执行相应的操作
            if len(inspect.getfullargspec(nested_func).args):
                return nested_func(cmd_arg)
            else:
                return nested_func()

    # 设置封装后的函数的签名属性，保留原始函数的签名信息
    wrapper.__signature__ = inspect.signature(func)
    return wrapper
