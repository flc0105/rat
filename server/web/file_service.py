import os

from server.web.artifact_service import WebArtifactService


class WebFileService:
    """
    Web 文件服务。

    职责：
    - 兼容旧 file_service 调用入口
    - 将正式文件能力转交给 artifact_service
    - 自身仅保留 upload_tmp 等轻量能力入口
    """

    def __init__(self, artifact_service: WebArtifactService):
        self.artifact_service = artifact_service
        self.web_root_dir = artifact_service.web_root_dir
        self.upload_tmp_dir = artifact_service.upload_tmp_dir
        self.http_uploads_dir = artifact_service.http_uploads_dir

    def create_upload_temp_file(self, upload) -> tuple[str, str]:
        return self.artifact_service.create_upload_temp_file(upload)

    # ------------------ background job compatibility ------------------ #
    def get_safe_http_upload_file_path(self, relative_path: str) -> str:
        base_dir = os.path.abspath(self.http_uploads_dir)
        file_path = os.path.abspath(os.path.join(base_dir, relative_path))
        if not file_path.startswith(base_dir + os.sep) and file_path != base_dir:
            raise ValueError('invalid http upload file path')
        return file_path

    def build_http_upload_preview_payload(self, relative_path: str) -> dict:
        file_path = self.get_safe_http_upload_file_path(relative_path)
        display_name = os.path.basename(relative_path)
        preview_type = self.artifact_service.guess_preview_type(display_name)

        if preview_type == 'image':
            return {
                'type': 'image',
                'name': display_name,
                'url': f'/api/background-job-files/{relative_path}/raw'
            }

        if preview_type == 'text':
            truncated = False
            with open(file_path, 'rb') as file_obj:
                raw = file_obj.read(self.artifact_service.MAX_PREVIEW_TEXT_BYTES + 1)

            if len(raw) > self.artifact_service.MAX_PREVIEW_TEXT_BYTES:
                raw = raw[:self.artifact_service.MAX_PREVIEW_TEXT_BYTES]
                truncated = True

            text = raw.decode('utf-8', errors='replace')
            if truncated:
                text += '\n\n...(已截断)'

            return {
                'type': 'text',
                'name': display_name,
                'content': text,
                'truncated': truncated,
            }

        return {
            'type': 'unsupported',
            'name': display_name,
        }
