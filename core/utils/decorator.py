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
        setattr(func, 'help', text)
        setattr(func, 'hide_from_help', False)
        return func

    return attr_decorator


def web_desc(text):
    """
    Web/结构化调用专用命令装饰器：
    - 仍然导出到 command manifest
    - 默认不显示在 help 列表中
    """

    def attr_decorator(func):
        setattr(func, 'help', text)
        setattr(func, 'hide_from_help', True)
        return func

    return attr_decorator