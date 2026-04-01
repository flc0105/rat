from functools import wraps


def interruptible(*, fallback_timeout=None):
    """
    方法级中断装饰器。

    职责：
    - 在方法真正执行前先统一检查一次 cancel / timeout
    - 不替代长循环/长 I/O 内部的持续检查，只负责入口守卫
    """

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            runner = getattr(self, '_run_interruptible', None)
            if callable(runner):
                return runner(
                    lambda: func(self, *args, **kwargs),
                    fallback_timeout=fallback_timeout,
                )
            return func(self, *args, **kwargs)

        return wrapper

    return decorator


def cancel_policy(supported: bool = True, message: str = ''):
    """
    单独设置命令的可取消性。

    用法：
        @cancel_policy(False, message='This command cannot be cancelled')
        def my_command(self, arg):
            # 这个命令不支持取消
            pass
    """

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # 在调用前直接设置取消策略
            if hasattr(self, '_set_cancel_policy'):
                self._set_cancel_policy(
                    supported=supported,
                    message=message
                )
            return func(self, *args, **kwargs)

        return wrapper

    return decorator


def timeout(seconds: float):
    """
    单独设置命令的超时时间。

    用法：
        @timeout(30)
        def my_command(self, arg):
            # 这个命令超时时间为30秒
            pass

    注意：必须在 @interruptible 之后使用
    """

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # 在调用前直接设置超时
            if hasattr(self, '_set_timeout'):
                self._set_timeout(seconds)
            return func(self, *args, **kwargs)

        return wrapper

    return decorator



