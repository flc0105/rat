import os
import shutil

from server.application.artifact.artifact_preview_service import ArtifactPreviewService
from server.application.artifact.artifact_registry_service import ArtifactRegistryService
from server.application.artifact.artifact_temp_file_service import ArtifactTempFileService
from server.config.config import WEB_CLEAR_PREVIEW_CACHE_ON_STARTUP, WEB_FILES_ROOT_DIR, WEB_PREVIEW_TEXT_MAX_BYTES


class WebArtifactService:
    """
    Web Artifact 门面服务。

    职责：
    - 管理正式 artifact（files / previews）
    - 管理 upload_tmp 临时文件（供 server -> client 的 HTTP 拉取链路使用）
    """

    MAX_PREVIEW_TEXT_BYTES = WEB_PREVIEW_TEXT_MAX_BYTES

    CATEGORY_FILES = 'files'
    CATEGORY_PREVIEWS = 'previews'
    CATEGORY_UPLOAD_TMP = 'upload_tmp'

    def __init__(self):
        self.web_root_dir = WEB_FILES_ROOT_DIR
        self.artifacts_root_dir = os.path.join(self.web_root_dir, 'artifacts')
        self.files_dir = os.path.join(self.artifacts_root_dir, self.CATEGORY_FILES)
        self.previews_dir = os.path.join(self.artifacts_root_dir, self.CATEGORY_PREVIEWS)
        self.upload_tmp_dir = os.path.join(self.artifacts_root_dir, self.CATEGORY_UPLOAD_TMP)

        self._prepare_dirs()

        self.registry_service = ArtifactRegistryService(self)
        self.preview_service = ArtifactPreviewService(self)
        self.temp_file_service = ArtifactTempFileService(self)

        if WEB_CLEAR_PREVIEW_CACHE_ON_STARTUP:
            self._clear_preview_cache_on_startup()

    # ------------------ dirs ------------------ #
    def _prepare_dirs(self):
        os.makedirs(self.artifacts_root_dir, exist_ok=True)
        os.makedirs(self.files_dir, exist_ok=True)
        os.makedirs(self.previews_dir, exist_ok=True)
        os.makedirs(self.upload_tmp_dir, exist_ok=True)

    def _clear_preview_cache_on_startup(self):
        """
        服务端启动时清空 previews 缓存目录，避免预览文件无限堆积
        """
        try:
            if os.path.isdir(self.previews_dir):
                shutil.rmtree(self.previews_dir, ignore_errors=True)
            os.makedirs(self.previews_dir, exist_ok=True)
        except Exception:
            pass

    # ------------------ registry facade ------------------ #
    def allocate_artifact_path(self, artifact_type: str, hostname: str, original_name: str, category: str = '') -> dict:
        return self.registry_service.allocate_artifact_path(
            artifact_type,
            hostname,
            original_name,
            category=category
        )

    def register_existing_artifact(
        self,
        *,
        artifact_type: str,
        category: str,
        hostname: str,
        original_name: str,
        file_path: str,
        meta_path: str,
        stored_name: str,
        source_type: str = '',
        source_command_id=None,
        client_id: str = '',
        addr: str = '',
        job_id: str = '',
        job_name: str = '',
        job_key: str = '',
        related_path: str = '',
        extra: dict | None = None,
    ) -> dict:
        return self.registry_service.register_existing_artifact(
            artifact_type=artifact_type,
            category=category,
            hostname=hostname,
            original_name=original_name,
            file_path=file_path,
            meta_path=meta_path,
            stored_name=stored_name,
            source_type=source_type,
            source_command_id=source_command_id,
            client_id=client_id,
            addr=addr,
            job_id=job_id,
            job_name=job_name,
            job_key=job_key,
            related_path=related_path,
            extra=extra,
        )

    def save_http_uploaded_file(
        self,
        file,
        artifact_type: str = '',
        category: str = '',
        client_id: str = '',
        hostname: str = '',
        job_id: str = '',
        job_name: str = '',
        job_key: str = '',
        source_type: str = '',
        source_command_id=None,
        addr: str = '',
        related_path: str = '',
        extra: dict | None = None,
    ) -> dict:
        return self.registry_service.save_http_uploaded_file(
            file,
            artifact_type=artifact_type,
            category=category,
            client_id=client_id,
            hostname=hostname,
            job_id=job_id,
            job_name=job_name,
            job_key=job_key,
            source_type=source_type,
            source_command_id=source_command_id,
            addr=addr,
            related_path=related_path,
            extra=extra,
        )

    def list_artifacts(self, artifact_type: str = '', hostname: str = '') -> list[dict]:
        return self.registry_service.list_artifacts(
            artifact_type=artifact_type,
            hostname=hostname
        )

    def list_artifact_hostnames(self) -> list[str]:
        return self.registry_service.list_artifact_hostnames()

    def get_artifact_by_id(self, artifact_id: str) -> dict:
        return self.registry_service.get_artifact_by_id(artifact_id)

    def get_artifact_file_path(self, artifact_id: str) -> str:
        return self.registry_service.get_artifact_file_path(artifact_id)

    def delete_artifact(self, artifact_id: str) -> dict:
        return self.registry_service.delete_artifact(artifact_id)

    def clear_artifacts(self, artifact_type: str, hostname: str = '') -> dict:
        return self.registry_service.clear_artifacts(artifact_type, hostname=hostname)

    # ------------------ preview facade ------------------ #
    def guess_preview_type(self, filename: str) -> str:
        return self.preview_service.guess_preview_type(filename)

    def build_preview_payload(self, artifact_id: str) -> dict:
        return self.preview_service.build_preview_payload(artifact_id)

    # ------------------ temp file facade ------------------ #
    def create_upload_temp_file(self, upload) -> tuple[str, str]:
        return self.temp_file_service.create_upload_temp_file(upload)

    def stage_local_file(self, source_path: str, display_name: str = '') -> tuple[str, str]:
        return self.temp_file_service.stage_local_file(source_path, display_name)

    def get_upload_temp_file_path(self, temp_id: str, filename: str) -> str:
        return self.temp_file_service.get_temp_file_path(temp_id, filename)

    def build_upload_temp_download_relative_url(self, temp_path: str) -> str:
        return self.temp_file_service.build_temp_download_relative_url(temp_path)

    def cleanup_upload_temp_file(self, temp_path: str):
        self.temp_file_service.cleanup_temp_file(temp_path)