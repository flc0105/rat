#!/usr/bin/env python3
"""
Chrome/Edge 书签提取模块
"""

import os
import json
from pathlib import Path
from datetime import datetime


def chrome_time_to_datetime(chrome_time):
    """
    将 Chrome 时间戳转换为 datetime 对象
    Chrome 时间戳是从 1601-01-01 开始的微秒数
    """
    if chrome_time is None or chrome_time == 0:
        return None

    try:
        seconds_since_1601 = chrome_time / 1000000
        seconds_since_1970 = seconds_since_1601 - 11644473600
        return datetime.fromtimestamp(seconds_since_1970)
    except:
        return None


def get_browser_paths(browser):
    """获取浏览器配置路径（跨平台）"""
    home = Path.home()

    paths = {
        'chrome': {
            'win': home / 'AppData/Local/Google/Chrome/User Data',
            'darwin': home / 'Library/Application Support/Google/Chrome',
            'linux': home / '.config/google-chrome'
        },
        'edge': {
            'win': home / 'AppData/Local/Microsoft/Edge/User Data',
            'darwin': home / 'Library/Application Support/Microsoft Edge',
            'linux': home / '.config/microsoft-edge'
        }
    }

    import sys
    platform = sys.platform

    if platform == 'win32':
        platform_key = 'win'
    elif platform == 'darwin':
        platform_key = 'darwin'
    else:
        platform_key = 'linux'

    if browser.lower() in paths and platform_key in paths[browser.lower()]:
        return str(paths[browser.lower()][platform_key])
    return None


def extract_bookmarks_recursive(node, path=''):
    """递归提取书签"""
    bookmarks = []

    if node.get('type') == 'folder':
        folder_name = node.get('name', 'Unnamed Folder')
        current_path = f"{path}/{folder_name}" if path else folder_name
        children = node.get('children', [])
        for child in children:
            bookmarks.extend(extract_bookmarks_recursive(child, current_path))
    elif node.get('type') == 'url':
        date_added = node.get('date_added')
        date_added_formatted = None
        if date_added:
            dt = chrome_time_to_datetime(date_added)
            date_added_formatted = dt.strftime('%Y-%m-%d %H:%M:%S') if dt else None

        bookmarks.append({
            'name': node.get('name', ''),
            'url': node.get('url', ''),
            'path': path,
            'date_added': date_added_formatted
        })

    return bookmarks


def get_chromium_bookmarks(filename):
    """获取 Chrome/Edge 书签"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)

        roots = data.get('roots', {})
        all_bookmarks = []

        bookmark_bar = roots.get('bookmark_bar', {})
        if bookmark_bar:
            all_bookmarks.extend(extract_bookmarks_recursive(bookmark_bar, 'Bookmarks Bar'))

        other = roots.get('other', {})
        if other:
            all_bookmarks.extend(extract_bookmarks_recursive(other, 'Other Bookmarks'))

        synced = roots.get('synced', {})
        if synced:
            all_bookmarks.extend(extract_bookmarks_recursive(synced, 'Mobile Bookmarks'))

        return all_bookmarks
    except Exception as e:
        return {'error': f'Failed to read bookmarks: {str(e)}'}


def extract_bookmarks(browser='chrome'):
    """
    提取浏览器书签

    Args:
        browser: 浏览器类型，'chrome' 或 'edge'

    Returns:
        list: 书签列表，每个元素包含 name, url, path, date_added
    """
    import sys

    profile_path = get_browser_paths(browser)
    if not profile_path or not os.path.isdir(profile_path):
        return {'error': f'Browser not found: {browser}'}

    if sys.platform == 'win32':
        default_path = os.path.join(profile_path, 'Default')
    else:
        default_path = os.path.join(profile_path, 'Default')
        if not os.path.isdir(default_path):
            default_path = os.path.join(profile_path, 'Profile 1')

    bookmarks_path = os.path.join(default_path, 'Bookmarks')
    if not os.path.isfile(bookmarks_path):
        return {'error': 'Bookmarks file not found'}

    bookmarks = get_chromium_bookmarks(bookmarks_path)
    return bookmarks

print(json.dumps(extract_bookmarks(), indent=2, ensure_ascii=False))