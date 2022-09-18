def parse(command):
    """
    将命令拆分为命令名和参数
    """
    name = command.split()[0]
    arg = command[len(name) + 1:].strip()
    return name, arg
