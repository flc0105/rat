import os
import time
import threading
import hashlib
from pathlib import Path

from client.jobs.core.job import Job
from core.utils.formatting import get_time, get_size
from core.utils.logger import logger


class DirectoryMonitor(Job):
    """
    监控目录变化：创建、删除、修改、移动文件
    """

    def __init__(self, target_dir=None, interval=2, watch_subdirs=True):
        """
        :param target_dir: 监控的目录，默认桌面
        :param interval: 检查间隔（秒）
        :param watch_subdirs: 是否监控子目录
        """
        super().__init__()

        if target_dir is None:
            target_dir = os.path.expanduser('~/Desktop')

        self.target_dir = os.path.abspath(target_dir)
        self.interval = interval
        self.watch_subdirs = watch_subdirs
        self.snapshot = {}  # 文件快照 {path: (mtime, size, hash)}
        self.last_snapshot_time = 0
        self.event_count = 0

    def run(self):
        try:
            time.sleep(2)
            self.send_to_server(1, f'Directory monitor started', 0)

            # 检查目录是否存在
            if not os.path.exists(self.target_dir):
                self.send_to_server(0, f'Directory not found: {self.target_dir}', 0)
                self.mark_stopped()
                return

            self.send_to_server(1, f'Watching: {self.target_dir}', 0)
            self.send_to_server(1, f'Interval: {self.interval}s, Subdirs: {self.watch_subdirs}', 0)

            # 初始化快照
            self._take_snapshot()
            self.mark_running()

            while not self.stop_event.is_set():
                self._check_changes()
                time.sleep(self.interval)

            self.send_to_server(1, 'Directory monitor stopped', 0)
        except Exception as e:
            self.send_to_server(0, f'Monitor error: {e}', 0)
        finally:
            self.mark_stopped()
            logger.info(f'Thread ended: {threading.current_thread().name}')
            self.send_to_server(1, f'Task ended: {threading.current_thread().name}', 1)

    def stop(self, notify: bool = True):
        self.request_stop(notify=notify)

    def _get_file_info(self, file_path):
        """获取文件信息"""
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'is_file': os.path.isfile(file_path),
                'is_dir': os.path.isdir(file_path)
            }
        except:
            return None

    def _get_file_hash(self, file_path, block_size=8192):
        """计算文件哈希（用于检测内容变化）"""
        try:
            if not os.path.isfile(file_path):
                return None

            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # 只读前 1MB 用于快速比较
                data = f.read(1024 * 1024)
                hasher.update(data)
            return hasher.hexdigest()[:16]
        except:
            return None

    def _take_snapshot(self):
        """创建目录快照"""
        snapshot = {}

        if self.watch_subdirs:
            # 递归遍历所有文件
            for root, dirs, files in os.walk(self.target_dir):
                # 添加目录
                rel_path = os.path.relpath(root, self.target_dir)
                if rel_path == '.':
                    path_key = self.target_dir
                else:
                    path_key = os.path.join(self.target_dir, rel_path)

                info = self._get_file_info(root)
                if info:
                    snapshot[path_key] = {
                        'type': 'dir',
                        'size': 0,
                        'mtime': info['mtime'],
                        'hash': None
                    }

                # 添加文件
                for filename in files:
                    file_path = os.path.join(root, filename)
                    info = self._get_file_info(file_path)
                    if info:
                        snapshot[file_path] = {
                            'type': 'file',
                            'size': info['size'],
                            'mtime': info['mtime'],
                            'hash': self._get_file_hash(file_path)
                        }
        else:
            # 只监控根目录
            for item in os.listdir(self.target_dir):
                item_path = os.path.join(self.target_dir, item)
                info = self._get_file_info(item_path)
                if info:
                    item_type = 'file' if info['is_file'] else 'dir'
                    snapshot[item_path] = {
                        'type': item_type,
                        'size': info['size'],
                        'mtime': info['mtime'],
                        'hash': self._get_file_hash(item_path) if info['is_file'] else None
                    }

        self.snapshot = snapshot
        self.last_snapshot_time = time.time()

    def _check_changes(self):
        """检查变化"""
        try:
            current_snapshot = {}

            # 收集当前状态
            if self.watch_subdirs:
                for root, dirs, files in os.walk(self.target_dir):
                    # 目录
                    if root != self.target_dir:
                        current_snapshot[root] = {
                            'type': 'dir',
                            'size': 0,
                            'mtime': os.path.getmtime(root) if os.path.exists(root) else 0,
                            'hash': None
                        }

                    # 文件
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        info = self._get_file_info(file_path)
                        if info:
                            current_snapshot[file_path] = {
                                'type': 'file',
                                'size': info['size'],
                                'mtime': info['mtime'],
                                'hash': self._get_file_hash(file_path)
                            }
            else:
                for item in os.listdir(self.target_dir):
                    item_path = os.path.join(self.target_dir, item)
                    info = self._get_file_info(item_path)
                    if info:
                        item_type = 'file' if info['is_file'] else 'dir'
                        current_snapshot[item_path] = {
                            'type': item_type,
                            'size': info['size'],
                            'mtime': info['mtime'],
                            'hash': self._get_file_hash(item_path) if info['is_file'] else None
                        }

            # 比较变化
            old_paths = set(self.snapshot.keys())
            new_paths = set(current_snapshot.keys())

            # 新创建的文件/目录
            created = new_paths - old_paths
            for path in created:
                info = current_snapshot[path]
                rel_path = os.path.relpath(path, self.target_dir)

                if info['type'] == 'file':
                    size_str = get_size(info['size'])
                    self.send_to_server(1, f'[CREATE] File: {rel_path} ({size_str})', 0)
                else:
                    self.send_to_server(1, f'[CREATE] Directory: {rel_path}', 0)
                self.event_count += 1

            # 删除的文件/目录
            deleted = old_paths - new_paths
            for path in deleted:
                info = self.snapshot[path]
                rel_path = os.path.relpath(path, self.target_dir)

                if info['type'] == 'file':
                    self.send_to_server(1, f'[DELETE] File: {rel_path}', 0)
                else:
                    self.send_to_server(1, f'[DELETE] Directory: {rel_path}', 0)
                self.event_count += 1

            # 修改的文件（存在于两边）
            common = old_paths & new_paths
            for path in common:
                old_info = self.snapshot[path]
                new_info = current_snapshot[path]

                # 只检查文件
                if old_info['type'] == 'file' and new_info['type'] == 'file':
                    rel_path = os.path.relpath(path, self.target_dir)

                    # 检查大小变化
                    if old_info['size'] != new_info['size']:
                        old_size = get_size(old_info['size'])
                        new_size = get_size(new_info['size'])
                        self.send_to_server(1, f'[MODIFY] File size: {rel_path} ({old_size} -> {new_size})', 0)
                        self.event_count += 1
                    # 检查修改时间变化
                    elif old_info['mtime'] != new_info['mtime']:
                        self.send_to_server(1, f'[MODIFY] File modified: {rel_path}', 0)
                        self.event_count += 1
                    # 检查内容哈希变化
                    elif old_info['hash'] != new_info['hash'] and new_info['hash']:
                        self.send_to_server(1, f'[MODIFY] File content: {rel_path}', 0)
                        self.event_count += 1

            # 更新快照
            self.snapshot = current_snapshot

        except Exception as e:
            self.send_to_server(0, f'Check error: {e}', 0)

    def get_status(self):
        """获取监控状态"""
        return {
            'target_dir': self.target_dir,
            'interval': self.interval,
            'watch_subdirs': self.watch_subdirs,
            'event_count': self.event_count,
            'snapshot_size': len(self.snapshot)
        }