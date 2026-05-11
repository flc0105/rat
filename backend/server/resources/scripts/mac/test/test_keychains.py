from client.runtime.keychains import get_secret, get_login

token = get_secret("test_secret").getvalue()

login = get_login("test_login")
username = login.username
password = login.password.getvalue()

server_token = get_secret("server_code", scope="server").getvalue()

print(token)
print(login)
print(username)
print(password)
print(server_token)