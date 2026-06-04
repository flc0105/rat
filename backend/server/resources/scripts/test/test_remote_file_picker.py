SCRIPT_METADATA = {
    "name": "test_remote_file_picker",
    "display_name": "Test Remote File Picker",
    "description": "测试 RemoteFilePicker：选择一个远程文件后直接打印路径。",
    "category": "Test",
    "tags": ["test", "remote-file-picker"],
    "platforms": ["*"],
    "params": [
        {
            "name": "target_file",
            "type": "remote_file",
            "description": "选择一个远程文件，运行后会直接打印该路径。",
            "required": True,
            "initial_path": "/"
        }
    ]
}


def main():
    selected_path = kwargs.get("target_file", "")
    print(selected_path)


if __name__ == "__main__":
    main()