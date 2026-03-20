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
