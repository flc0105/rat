#!/usr/bin/env python3
"""
command-stats - 统计最常用的命令
用法: command-stats [数量]
      command-stats 20
      command-stats --today  # 只统计今天
"""

import sys
import os
from collections import Counter
from datetime import datetime


def get_history_file():
    """获取历史命令文件路径"""
    home = os.path.expanduser('~')

    # zsh
    if os.path.exists(os.path.join(home, '.zsh_history')):
        return os.path.join(home, '.zsh_history')
    # bash
    if os.path.exists(os.path.join(home, '.bash_history')):
        return os.path.join(home, '.bash_history')
    return None


def parse_zsh_history(file_path):
    """解析zsh历史"""
    commands = []
    today = datetime.now().strftime('%Y-%m-%d')

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # zsh格式: : 1234567890:0;command
            if line.startswith(': '):
                parts = line.split(';', 1)
                if len(parts) == 2:
                    timestamp_part = parts[0].split(':')[1]
                    if timestamp_part:
                        try:
                            timestamp = int(timestamp_part.split(':')[0])
                            date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')
                        except:
                            pass
                    command = parts[1].strip()
                    if command and not command.startswith('command-stats'):
                        commands.append(command.split()[0] if command.split() else command)
    return commands


def parse_bash_history(file_path):
    """解析bash历史"""
    commands = []

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            command = line.strip()
            if command and not command.startswith('command-stats'):
                commands.append(command.split()[0] if command.split() else command)


    return commands


def main():
    limit = 20



    history_file = get_history_file()
    print(history_file)
    if not history_file:
        print("未找到历史命令文件")
        sys.exit(1)

    # 解析历史
    if 'zsh' in history_file:
        commands = parse_zsh_history(history_file)
    else:
        commands = parse_bash_history(history_file)

    if not commands:
        print("没有命令记录")
        sys.exit(1)

    # 统计
    counter = Counter(commands)

    print(f"最常用的 {limit} 个命令:")
    print("-" * 40)

    for i, (cmd, count) in enumerate(counter.most_common(limit), 1):
        print(f"{i:2d}. {cmd:20s} {count:5d} 次")



main()