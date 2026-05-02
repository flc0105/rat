ctx = kwargs.get('__context__', {})

print(ctx.get('client_id'))
print(ctx.get('command_id'))
print(ctx)