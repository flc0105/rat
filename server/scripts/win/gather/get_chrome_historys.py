#!/usr/bin/env python3
"""
Chrome/Edge 历史记录提取模块
"""

import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path


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


def truncate_string(s, max_length=500):
    """截断过长的字符串"""
    if s and len(s) > max_length:
        return s[:max_length] + "..."
    return s


def get_chromium_history(db_path):
    """获取 Chrome/Edge 历史记录"""
    db_copy = os.path.join(tempfile.gettempdir(), 'history.db')
    try:
        shutil.copy2(db_path, db_copy)
        conn = sqlite3.connect(db_copy)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT url, title, last_visit_time, visit_count 
            FROM urls 
            ORDER BY last_visit_time DESC
        ''')

        history = []
        for url, title, last_visit_time, visit_count in cursor.fetchall():
            visit_time = chrome_time_to_datetime(last_visit_time)
            history.append({
                'title': truncate_string(title, 500),
                'url': truncate_string(url, 500),
                'last_visit_time': visit_time.strftime('%Y-%m-%d %H:%M:%S') if visit_time else None,
                'visit_count': visit_count
            })

        cursor.close()
        conn.close()
        return history
    except Exception as e:
        print(f'Error reading history: {e}')
        return []
    finally:
        if os.path.exists(db_copy):
            try:
                os.remove(db_copy)
            except:
                pass


def extract_history(browser='chrome'):
    """
    提取浏览器历史记录

    Args:
        browser: 浏览器类型，'chrome' 或 'edge'

    Returns:
        list: 历史记录列表
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

    history_path = os.path.join(default_path, 'History')
    if not os.path.isfile(history_path):
        return {'error': 'History file not found'}

    try:
        history = get_chromium_history(history_path)
        return history
    except Exception as e:
        return {'error': f'Failed to extract history: {str(e)}'}



import sys

browser = sys.argv[1] if len(sys.argv) > 1 else 'chrome'
result = extract_history(browser)
print(json.dumps(result, indent=2, ensure_ascii=False))
