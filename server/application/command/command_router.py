from functools import partial


class CommandRouter:
    """
    命令路由器。

    职责：
    - 决定非 builtin 命令如何分流
    - 处理 acmd / alias / default 三条主线
    - 不负责具体执行，只负责把 plan 交给 plan_executor

    说明：
    - builtin 命令仍由 BuiltinCommandHandler 处理
    - 这里聚焦的是“远程计划型命令”的路由决策
    """

    def __init__(self, plan_builder, plan_executor, error_executor):
        self.plan_builder = plan_builder
        self.plan_executor = plan_executor
        self.error_executor = error_executor

    def _wrap_error(self, error):
        return partial(self.error_executor, error)

    def _resolve_alias_command(self, name, arg):
        try:
            plan = self.plan_builder.build_alias_plan(name, arg)
            if not plan:
                return None
            return self.plan_executor(plan)
        except Exception as e:
            return self._wrap_error(e)

    def _resolve_default_command(self, raw_command):
        plan = self.plan_builder.build_default_plan(raw_command)
        return self.plan_executor(plan)

    def _resolve_argument_command(self, raw_command):
        plan = self.plan_builder.build_argument_command_plan(raw_command)
        return self.plan_executor(plan)

    def resolve(self, raw_command: str, name: str, arg: str):
        if self.plan_builder.is_argument_command(raw_command):
            return self._resolve_argument_command(raw_command)

        alias_handler = self._resolve_alias_command(name, arg)
        if alias_handler:
            return alias_handler

        return self._resolve_default_command(raw_command)