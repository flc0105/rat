class WebJobApi:
    """
    Web 后台任务子外观。

    职责：
    - 管理 server script jobs
    - 管理 background jobs
    - 封装 background job 启动时所需的 command submit 语义
    - 对外提供 background job catalog

    说明：
    - 路由层不再直接协调 script_service / background_job_service / command_api
    - 相关应用语义统一收口到这里
    """

    def __init__(self, command_api, background_job_service, script_service):
        self.command_api = command_api
        self.background_job_service = background_job_service
        self.script_service = script_service

    # ------------------ server job api ------------------ #
    def list_server_jobs(self) -> list[dict]:
        return self.script_service.list_scripts()

    def get_server_job_content(self, script_name: str) -> str:
        return self.script_service.get_script_content(script_name)

    def save_server_job_content(self, script_name: str, content):
        return self.script_service.save_script(script_name, content)

    def upload_server_job(self, file_storage):
        return self.script_service.upload_script(file_storage)

    def delete_server_job(self, script_name: str):
        return self.script_service.delete_script(script_name)

    # ------------------ background job api ------------------ #
    def list_background_jobs(self, client_id: str):
        return self.background_job_service.list_jobs(client_id)

    def list_available_background_jobs(self, client_id: str):
        return self.background_job_service.list_available_jobs(client_id)

    def start_background_job(self, client_id: str, job_name: str, source: str = 'auto'):
        source = (source or 'auto').strip().lower()
        if source not in ('auto', 'client', 'server'):
            source = 'auto'

        command = f'start_job {job_name}'
        # if source == 'server':
        #     command = f'start_job_remote {job_name}'

        result = self.command_api.submit_web_command(client_id, command)
        if isinstance(result, dict):
            result['job_name'] = job_name
            result['source'] = source
        return result

    def stop_background_job(self, client_id: str, job_key: str):
        return self.background_job_service.stop_job(client_id, job_key)

    def ingest_background_job_report(self, payload: dict):
        return self.background_job_service.ingest_report(payload)

    def list_background_job_catalog(self, client_id: str):
        client_items = self.list_available_background_jobs(client_id) or []
        server_items = self.list_server_jobs() or []

        normalized = []
        seen = set()

        for item in client_items:
            if not isinstance(item, dict):
                continue

            job_name = str(item.get('job_name') or item.get('name') or item.get('job_key') or '').strip()
            if not job_name:
                continue

            source = str(item.get('source') or 'client').strip() or 'client'
            dedupe_key = (source, job_name)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            normalized.append({
                **item,
                'job_name': job_name,
                'job_key': str(item.get('job_key') or job_name).strip() or job_name,
                'display_name': str(item.get('display_name') or job_name).strip() or job_name,
                'source': source,
            })

        for item in server_items:
            if not isinstance(item, dict):
                continue

            job_name = str(item.get('job_name') or item.get('name') or item.get('job_key') or '').strip()
            if not job_name:
                continue

            dedupe_key = ('server', job_name)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            normalized.append({
                **item,
                'job_name': job_name,
                'job_key': str(item.get('job_key') or job_name).strip() or job_name,
                'display_name': str(item.get('display_name') or item.get('name') or job_name).strip() or job_name,
                'source': 'server',
            })

        normalized.sort(key=lambda item: (item.get('source') != 'client', item.get('job_name', '').lower()))
        return normalized