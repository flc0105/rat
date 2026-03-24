import sys
import time
from typing import Any, Iterable, Mapping


class TimeFormatter:
    @staticmethod
    def compact_now() -> str:
        return time.strftime('%Y%m%d-%H%M%S')

    @staticmethod
    def readable_now() -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S')


def get_time() -> str:
    return TimeFormatter.compact_now()


def get_readable_time() -> str:
    return TimeFormatter.readable_now()


def format_dict(data: Mapping[str, Any], width: int = 15, index: bool = False) -> str:
    if not data:
        return ''

    if not index:
        return '\n'.join(f'{key:{width}}{value}' for key, value in data.items())

    return '\n'.join(
        f'{i:<5}{key:{width}}{value}'
        for i, (key, value) in enumerate(data.items())
    )


def get_size(size_in_bytes: float, suffix: str = "B") -> str:
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if size_in_bytes < factor:
            return f"{size_in_bytes:.2f}{unit}{suffix}"
        size_in_bytes /= factor
    return f"{size_in_bytes:.2f}E{suffix}"


def draw_progress_bar(progress: int, total: int, bar_len: int = 50) -> None:
    if total <= 0:
        return

    completed = int(bar_len * progress / total)
    percent = round(100 * progress / total)
    bar = '=' * completed
    spaces = '-' * (bar_len - completed)

    sys.stdout.write(f'\r[{bar}{spaces}] {percent} %')
    sys.stdout.flush()

    if progress >= total:
        sys.stdout.write('\n')


def print_table(headers: Iterable[Any], data: Iterable[Iterable[Any]]) -> None:
    headers = list(headers)
    rows = [list(row) for row in data]

    if not headers:
        print("No headers to display")
        return

    if not rows:
        print("No data to display")
        return

    column_count = len(headers)
    rows = [row for row in rows if len(row) == column_count]
    if not rows:
        print("Table rows do not match header count")
        return

    column_widths = [
        max(len(str(headers[i])), *(len(str(row[i])) for row in rows))
        for i in range(column_count)
    ]

    row_format = " | ".join(f"{{:<{width}}}" for width in column_widths)

    print("\n" + row_format.format(*headers))
    print("-" * (sum(column_widths) + 3 * (column_count - 1)))

    for row in rows:
        print(row_format.format(*row))
    print()


def format_table(headers: Iterable[Any], data: Iterable[Iterable[Any]]) -> str:
    """
    将表格数据格式化为字符串并返回，而不是直接打印
    """
    headers = list(headers)
    rows = [list(row) for row in data]

    if not headers:
        return "No headers to display"

    if not rows:
        return "No data to display"

    column_count = len(headers)
    rows = [row for row in rows if len(row) == column_count]
    if not rows:
        return "Table rows do not match header count"

    column_widths = [
        max(len(str(headers[i])), *(len(str(row[i])) for row in rows))
        for i in range(column_count)
    ]

    row_format = " | ".join(f"{{:<{width}}}" for width in column_widths)

    lines = []
    lines.append(row_format.format(*headers))
    lines.append("-" * (sum(column_widths) + 3 * (column_count - 1)))

    for row in rows:
        lines.append(row_format.format(*row))

    return "\n".join(lines)