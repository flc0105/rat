# client/commands/mixins/process_ops.py

import json

from client.commands.common.services.process.process_service import ProcessService
from core.platform.platform_identity import detect_platform_alias
from core.utils.decorator import desc


class CommandProcessMixin:

    def __init__(self, *args, **kwargs):
        self._process_service = None
        super().__init__(*args, **kwargs)

    def _get_process_service(self):
        if self._process_service is None:
            self._process_service = ProcessService(self)
        return self._process_service

    @desc('List running processes', group='process', suggest=False)
    def list_processes(self, arg=''):

        """
        列出所有运行中的进程
        """
        try:
            processes = self._get_process_service().list_processes()
            return 1, json.dumps(processes)
        except Exception as e:
            return 0, f'Failed to list processes: {e}'

    @desc('Get process detail by PID', group='process', suggest=False)
    def get_process_detail(self, arg=''):
        """
        获取单个进程详情，包括：
        - 基本信息
        - 文件路径 / 启动参数 / 工作目录
        - 网络连接
        - 打开的文件
        """
        try:
            pid = int(str(arg or '').strip())
        except Exception:
            return 0, 'PID is required'

        try:
            details = json.dumps(self._get_process_service().get_process_detail(pid))
            return 1, details
        except Exception as e:
            return 0, str(e)

    @desc('List running applications (GUI apps only)', group='process', suggest=False)
    def list_apps(self, arg=''):
        """
        列出运行中的应用程序（仅 GUI 应用）
        """
        try:
            apps = []
            current_platform = detect_platform_alias()
            if current_platform == 'win':
                apps = self._get_process_service().list_windows_apps()
            elif current_platform == 'mac':
                apps = self._get_process_service().list_macos_app()
            else:
                raise Exception('Unsupported os:' + str(current_platform))

            return 1, json.dumps(apps)
        except Exception as e:
            return 0, f'Failed to list apps: {e}'

    @desc('Kill a process by PID', group='process', suggest=False)
    def kill_process(self, pid: str):
        try:
            self._get_process_service().kill_process(pid)
            return 1, f'Process {pid} terminated'
        except Exception as e:
            return 0, str(e)
