import base64

with open('../conf', 'r') as f:
    data = base64.b64encode(f.read().encode()).decode()

with open('../conf', 'w') as f:
    f.write(data)
