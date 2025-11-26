class RatCmdHelp:
    """ratcmd命令帮助系统"""

    @staticmethod
    def generate_help(command_name, required_args=None, optional_args=None, description=""):
        """
        生成命令帮助信息
        """
        required_args = required_args or []
        optional_args = optional_args or {}

        help_text = f"ratcmd {command_name}\n\n"
        help_text += f"描述: {description}\n\n"

        if required_args:
            help_text += "必需参数:\n"
            for arg in required_args:
                help_text += f"  --{arg} <value>\n"
            help_text += "\n"

        if optional_args:
            help_text += "可选参数:\n"
            for arg, info in optional_args.items():
                default = info.get('default', '')
                desc = info.get('description', '')
                help_text += f"  --{arg} <value>   默认值: {default}   描述: {desc}\n"

        return help_text

    @staticmethod
    def show_help(args_dict, command_name, required_args=None, optional_args=None, description=""):
        """
        检查是否需要显示帮助
        """
        if args_dict.get('help') is True:
            return True, RatCmdHelp.generate_help(command_name, required_args, optional_args, description)
        return False, None