import webbrowser

latitude = 36.102740874172305
longitude = 120.41943236196619

# 打开 Google Maps 并显示位置
url = f'https://www.google.com/maps?q={latitude},{longitude}'
webbrowser.open(url)
