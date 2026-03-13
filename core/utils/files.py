import os
import re
import time
from pathlib import Path
from typing import BinaryIO


class FileStreamFactory:
    @staticmethod
    def open_output_stream(filename: str) -> BinaryIO:
        return open(filename, 'rb')

    @staticmethod
    def open_input_stream(filename: str) -> BinaryIO:
        target_path = Path(filename)

        if target_path.exists():
            target_path = target_path.with_stem(f'{target_path.stem}_{int(time.time())}')

        file_obj = open(target_path, 'ab')
        file_obj.truncate(0)
        return file_obj


def get_output_stream(filename: str) -> BinaryIO:
    return FileStreamFactory.open_output_stream(filename)


def get_input_stream(filename: str) -> BinaryIO:
    return FileStreamFactory.open_input_stream(filename)


def secure_filename(filename: str) -> str:
    illegal_chars = r'[\\/:\*\?"<>|]'
    return re.sub(illegal_chars, '_', filename)


def replace_spaces(text: str, replacement: str = '_') -> str:
    return re.sub(r'\s+', replacement, text)