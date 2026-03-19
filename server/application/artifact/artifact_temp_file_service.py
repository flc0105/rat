import os
import uuid

from werkzeug.utils import secure_filename


class ArtifactTempFileService:
    """
    Artifact 临时文件服务。
    """

    def __init__(self, artifact_service):
        self.artifact_service = artifact_service

    def create_upload_temp_file(self, upload) -> tuple[str, str]:
        """
        为上传到客户端的浏览器文件创建临时落盘文件
        :return: (temp_path, safe_name)
        """
        safe_name = secure_filename(upload.filename) or 'upload.bin'
        temp_dir = os.path.join(self.artifact_service.upload_tmp_dir, uuid.uuid4().hex)
        os.makedirs(temp_dir, exist_ok=True)

        temp_path = os.path.join(temp_dir, safe_name)
        upload.save(temp_path)
        return temp_path, safe_name