import subprocess
import os
import tempfile


def webcam():
    """
    通过系统命令捕获摄像头照片（无需第三方库）
    """
    try:
        # macOS: 使用 imagesnap
        if os.name == 'posix' and os.uname().sysname == 'Darwin':
            # 检查是否安装了 imagesnap
            result = subprocess.run(['which', 'imagesnap'], capture_output=True)
            if result.returncode != 0:
                return '请安装 imagesnap: brew install imagesnap'

            temp_file = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False)
            temp_file.close()

            subprocess.run(['imagesnap', '-w', '1', temp_file.name],
                           capture_output=True, timeout=5)

            if os.path.getsize(temp_file.name) > 0:
                return temp_file.name
            else:
                os.unlink(temp_file.name)
                return None

        # Windows: 使用内置摄像头 API (需要 pywin32)
        elif os.name == 'nt':
            try:
                import win32com.client
                # 创建视频捕获设备
                cap = win32com.client.Dispatch("WIA.Video")
                # 拍照
                temp_file = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False)
                temp_file.close()
                cap.Save(temp_file.name)
                return temp_file.name
            except:
                return None

        # Linux: 使用 v4l2
        else:
            temp_file = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False)
            temp_file.close()
            subprocess.run(['fswebcam', '-r', '640x480', temp_file.name],
                           capture_output=True, timeout=5)

            if os.path.getsize(temp_file.name) > 0:
                return temp_file.name
            else:
                os.unlink(temp_file.name)
                return None

    except Exception as e:
        return None



path = webcam()
if path:
    print(f'照片保存到: {path}')
else:
    print('拍照失败')