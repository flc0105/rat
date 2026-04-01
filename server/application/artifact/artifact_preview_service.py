import mimetypes
import os


class ArtifactPreviewService:
    """
    Artifact 预览服务。
    """

    def __init__(self, artifact_service):
        self.artifact_service = artifact_service

    def guess_preview_type(self, filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()

        image_exts = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'}
        text_exts = {
            '.txt', '.log', '.py', '.js', '.ts', '.json', '.xml', '.yaml', '.yml',
            '.ini', '.cfg', '.conf', '.md', '.csv', '.sql', '.bat', '.sh', '.html', '.css'
        }

        if ext in image_exts:
            return 'image'
        if ext in text_exts:
            return 'text'

        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type:
            if mime_type.startswith('image/'):
                return 'image'
            if mime_type.startswith('text/'):
                return 'text'

        return 'unsupported'

    def build_preview_payload(self, artifact_id: str) -> dict:
        artifact = self.artifact_service.registry_service.get_artifact_by_id(artifact_id)
        file_path = artifact.get('saved_path', '')
        display_name = artifact.get('original_name') or artifact.get('stored_name') or 'artifact'

        if not os.path.isfile(file_path):
            raise FileNotFoundError('file not found')

        preview_type = self.guess_preview_type(display_name)

        if preview_type == 'image':
            return {
                'type': 'image',
                'name': os.path.basename(display_name),
                'url': artifact.get('raw_url', ''),
                'artifact_id': artifact.get('artifact_id', ''),
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
                'name': os.path.basename(display_name),
                'content': text,
                'truncated': truncated,
                'artifact_id': artifact.get('artifact_id', ''),
            }

        return {
            'type': 'unsupported',
            'name': os.path.basename(display_name),
            'artifact_id': artifact.get('artifact_id', ''),
        }






