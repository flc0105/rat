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
