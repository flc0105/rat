SCRIPT_METADATA = {
    "display_name": "Script SDK keychains resolve test",
    "description": "测试 Script SDK 通过 temp auth 读取 user/server scope 的 keychains secret 和 login。",
    "params": [],
    "api_grants": [
        "keychains:resolve"
    ]
}

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