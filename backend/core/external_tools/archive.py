import os
import zipfile
from typing import Any, Callable

from core.external_tools.paths import expand_path


def safe_extract_zip_archive(zip_path: Any, destination_dir: Any, path_expander: Callable[[Any], str] = expand_path) -> str:
    """Extract a zip file after rejecting entries that escape destination_dir."""
    archive_path = path_expander(zip_path)
    target_dir = path_expander(destination_dir)
    os.makedirs(target_dir, exist_ok=True)
    with zipfile.ZipFile(archive_path, 'r') as archive:
        for member in archive.infolist():
            member_path = os.path.abspath(os.path.join(target_dir, member.filename))
            if os.path.commonpath([target_dir, member_path]) != target_dir:
                raise ValueError(f'Unsafe zip entry detected: {member.filename}')
        archive.extractall(target_dir)
    return target_dir
