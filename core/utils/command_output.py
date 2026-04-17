import json
from dataclasses import dataclass
from typing import Literal

from core.utils.formatting import format_dict, format_table


OutputShape = Literal['dict', 'table']


@dataclass
class StructuredCommandResult:
    status: int
    data: dict | list[dict]
    shape: OutputShape | None = None
    columns: list[str] | None = None
    width: int | None = None


def parse_output_format(arg: str = '', default: str = 'text') -> str:
    text = str(arg or '').strip().lower()
    if text in ('json', '--json'):
        return 'json'
    return default


def render_structured_result(result, output_format: str = 'text'):
    """
    统一渲染命令输出。
    兼容旧命令：如果不是 StructuredCommandResult，原样返回。
    """
    if not isinstance(result, StructuredCommandResult):
        return result

    if output_format == 'json':
        return result.status, json.dumps(result.data, ensure_ascii=False, indent=2)

    data = result.data

    if isinstance(data, dict):
        if result.width is not None:
            return result.status, format_dict(data, width=result.width)
        return result.status, format_dict(data)

    if isinstance(data, list):
        if not data:
            return result.status, 'No data to display'

        headers = result.columns or list(data[0].keys())
        rows = [[item.get(header, '') for header in headers] for item in data]
        return result.status, format_table(headers, rows)

    return result.status, str(data)