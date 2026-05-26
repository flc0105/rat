ctx = kwargs.get('__context__', {})

print(ctx.get('client_id'))
print(ctx.get('command_id'))
print(ctx)


from client.runtime.sdk import context

print(context.client_id())
print(context.command_id())
print(context.hostname())
print(context.machine_id())
print(context.platform())
print(context.script_name())
print(context.arch())