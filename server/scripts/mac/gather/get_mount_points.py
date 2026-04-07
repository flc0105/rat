#!/usr/bin/env python3
import subprocess
import json


def human_readable_size(kb):
    """将KB转换为人类可读格式"""
    kb = int(kb)
    if kb >= 1024 * 1024 * 1024:  # TB
        return f"{kb / (1024 * 1024 * 1024):.1f} TB"
    elif kb >= 1024 * 1024:  # GB
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:  # MB
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


def get_mount_points():
    """获取磁盘挂载点信息"""
    mounts = []

    try:
        # 使用 df -k 获取详细信息
        df_output = subprocess.run(['df', '-k'], capture_output=True, text=True)
        lines = df_output.stdout.strip().split('\n')[1:]  # 跳过标题行

        for line in lines:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 9:
                continue

            # df -k 输出格式: Filesystem 1024-blocks Used Available Capacity iused ifree %iused Mounted on
            filesystem = parts[0]
            total_kb = parts[1]
            used_kb = parts[2]
            available_kb = parts[3]
            usage_percent = parts[4]
            mount_point = parts[8] if len(parts) > 8 else ""

            # 只显示真实磁盘和外部磁盘
            if filesystem.startswith('/dev/disk'):
                # 过滤掉系统虚拟磁盘
                if mount_point in ['/', '/System/Volumes/Data'] or mount_point.startswith('/Volumes/'):
                    if mount_point != '/Volumes':
                        mounts.append({
                            "device": filesystem,
                            "mount_point": mount_point,
                            "total": human_readable_size(total_kb),
                            "used": human_readable_size(used_kb),
                            "available": human_readable_size(available_kb),
                            "usage_percent": usage_percent
                        })

    except Exception as e:
        return [{"error": str(e)}]

    return mounts


result = get_mount_points()
print(json.dumps(result, indent=2, ensure_ascii=False))