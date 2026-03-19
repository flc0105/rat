from server.web.artifact_service import WebArtifactService


class WebFileService:
    """
    Web 文件服务。

    职责：
    - 仅保留浏览器上传到客户端前的 upload_tmp 临时落盘能力
    - 正式 artifact 的保存、预览、删除统一由 artifact_service 负责
    """

    def __init__(self, artifact_service: WebArtifactService):
        self.artifact_service = artifact_service
        self.web_root_dir = artifact_service.web_root_dir
        self.upload_tmp_dir = artifact_service.upload_tmp_dir

    def create_upload_temp_file(self, upload) -> tuple[str, str]:
        return self.artifact_service.create_upload_temp_file(upload)