from pathlib import Path

EXCLUDE_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    "__pycache__",
    "venv",
    ".venv",
    "env",
    ".env",
    "node_modules",
    "dist",
    "build",
    "target",
    ".mypy_cache",
    ".pytest_cache",
    "site-packages",
    "logs",
    "log",
    "tmp",
    "temp",
    "config",
    "utils",
    "scripts",
    "builtins",
    # "jobs",
    "platform",
    #
    "protocol",
    "python_execution",
    "http_transfer",
    "artifact",
    "history",
    "agent"
}

# 排除的文件名（可以是完整文件名或文件名不含扩展名）
EXCLUDE_FILENAMES = {
    "__init__",      # 排除所有 __init__.py, __init__.html 等
    "login.html",    # 排除 login.html
    "auth.js",        # 排除 auth.js
    "execution_ops.py",
    "file_cli_ops.py",
    "argument_command_registry.py",
    "agent.js",
    "process.js",
    "process_ops.py"

}

INCLUDE_SUFFIXES = {".py", ".html", ".js", ".css"}


def should_skip(path: Path) -> bool:
    # 排除指定目录
    if any(part in EXCLUDE_DIRS for part in path.parts):
        return True

    # 排除指定文件名（检查完整文件名和文件名不含扩展名）
    if path.name in EXCLUDE_FILENAMES:      # 检查完整文件名（如 login.html）
        return True
    if path.stem in EXCLUDE_FILENAMES:      # 检查不含扩展名的文件名（如 login）
        return True

    return False


def main():
    current_dir = Path.cwd()
    self_path = Path(__file__).resolve()
    output_path = current_dir / "all_source_code.txt"

    files = []
    for file_path in current_dir.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in INCLUDE_SUFFIXES:
            continue

        file_path = file_path.resolve()

        if file_path == self_path:
            continue

        if should_skip(file_path):
            continue

        files.append(file_path)

    with output_path.open("w", encoding="utf-8") as out:
        for file_path in sorted(files):
            try:
                code = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                try:
                    code = file_path.read_text(encoding="utf-8-sig")
                except Exception as e:
                    code = f"[读取失败] {e}"
            except Exception as e:
                code = f"[读取失败] {e}"

            relative_path = file_path.relative_to(current_dir)
            out.write(f"{relative_path}:\n\n")
            out.write(code)
            out.write("\n\n\n")


if __name__ == "__main__":
    main()