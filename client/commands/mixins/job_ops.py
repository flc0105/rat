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