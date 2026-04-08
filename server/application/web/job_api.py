class WebJobApi:
    """
    Web 后台任务子外观。

    职责：
    - 管理 job catalog
    - 管理 background jobs
    - 封装 background job 启动时所需的 command submit 语义
    - 对外提供 background job catalog

    说明：
    - 路由层不再直接协调 job_catalog_service / background_job_service / command_api
    - 相关应用语义统一收口到这里
    """

    def __init__(self, command_api, background_job_service, job_catalog_service):
        self.command_api = command_api
        self.background_job_service = background_job_service
        self.job_catalog_service = job_catalog_service

    # ------------------ job catalog api ------------------ #
    def list_jobs(self) -> list[dict]:
        return self.job_catalog_service.list_jobs()

    def get_job_content(self, job_name: str) -> str:
        return self.job_catalog_service.get_job_content(job_name)

    def save_job_content(self, job_name: str, content):
        return self.job_catalog_service.save_job(job_name, content)

    def upload_job(self, file_storage):
        return self.job_catalog_service.upload_job(file_storage)

    def delete_job(self, job_name: str):
        return self.job_catalog_service.delete_job(job_name)

    # ------------------ background job api ------------------ #
    def list_background_jobs(self, client_id: str):
        return self.background_job_service.list_jobs(client_id)

    def list_available_background_jobs(self, client_id: str):
        return self.background_job_service.list_available_jobs(client_id)

    def start_background_job(self, client_id: str, job_name: str):
        result = self.command_api.submit_web_command(client_id, f'start_job {job_name}')
        if isinstance(result, dict):
            result['job_name'] = job_name
        return result

    def stop_background_job(self, client_id: str, job_key: str):
        return self.background_job_service.stop_job(client_id, job_key)

    def ingest_background_job_report(self, payload: dict):
        return self.background_job_service.ingest_report(payload)

    def list_background_job_catalog(self, client_id: str):
        del client_id
        normalized = []
        seen = set()

        for item in self.list_jobs() or []:
            if not isinstance(item, dict):
                continue

            job_name = str(item.get('job_name') or item.get('name') or item.get('job_key') or '').strip()
            if not job_name:
                continue

            dedupe_key = job_name
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            normalized.append({
                **item,
                'job_name': job_name,
                'job_key': str(item.get('job_key') or job_name).strip() or job_name,
                'display_name': str(item.get('display_name') or item.get('name') or job_name).strip() or job_name,
                'source': 'job',
            })

        normalized.sort(key=lambda item: item.get('job_name', '').lower())
        return normalized
