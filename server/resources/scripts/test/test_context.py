ctx = kwargs.get('__context__', {})
client_id = ctx.get('client_id', '')
hostname = ctx.get('hostname', '')

print(client_id)
print(hostname)