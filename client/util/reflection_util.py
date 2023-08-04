def get_camel_case_class(module_name):
    class_name = "".join(word.capitalize() for word in module_name.split("_"))
    return class_name


def get_main_class(module, module_name):
    return getattr(module, get_camel_case_class(module_name))
