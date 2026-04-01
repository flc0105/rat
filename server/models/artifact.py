from dataclasses import dataclass, field
from typing import Any


@dataclass
class ArtifactRecord:
    artifact_id: str = ''
    artifact_type: str = ''
    category: str = ''
    hostname: str = ''
    client_id: str = ''
    addr: str = ''
    original_name: str = ''
    stored_name: str = ''
    saved_path: str = ''
    size: int = 0
    created_at: str = ''
    source_type: str = ''
    source_command_id: Any = None
    job_id: str = ''
    job_name: str = ''
    job_key: str = ''
    related_path: str = ''

    download_url: str = ''
    raw_url: str = ''
    preview_url: str = ''

    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict | None):
        if not isinstance(payload, dict):
            return cls()

        return cls(
            artifact_id=payload.get('artifact_id', ''),
            artifact_type=payload.get('artifact_type', ''),
            category=payload.get('category', ''),
            hostname=payload.get('hostname', ''),
            client_id=payload.get('client_id', ''),
            addr=payload.get('addr', ''),
            original_name=payload.get('original_name', ''),
            stored_name=payload.get('stored_name', ''),
            saved_path=payload.get('saved_path', ''),
            size=int(payload.get('size', 0) or 0),
            created_at=payload.get('created_at', ''),
            source_type=payload.get('source_type', ''),
            source_command_id=payload.get('source_command_id'),
            job_id=payload.get('job_id', ''),
            job_name=payload.get('job_name', ''),
            job_key=payload.get('job_key', ''),
            related_path=payload.get('related_path', ''),
            download_url=payload.get('download_url', ''),
            raw_url=payload.get('raw_url', ''),
            preview_url=payload.get('preview_url', ''),
            extra=payload.get('extra') if isinstance(payload.get('extra'), dict) else {},
        )

    def to_meta_dict(self) -> dict:
        payload = {
            'artifact_id': self.artifact_id,
            'artifact_type': self.artifact_type,
            'category': self.category,
            'hostname': self.hostname,
            'client_id': self.client_id,
            'addr': self.addr,
            'original_name': self.original_name,
            'stored_name': self.stored_name,
            'saved_path': self.saved_path,
            'size': int(self.size or 0),
            'created_at': self.created_at,
            'source_type': self.source_type,
            'source_command_id': self.source_command_id,
            'job_id': self.job_id,
            'job_name': self.job_name,
            'job_key': self.job_key,
            'related_path': self.related_path,
            'download_url': self.download_url,
            'raw_url': self.raw_url,
            'preview_url': self.preview_url,
        }
        if self.extra:
            payload['extra'] = dict(self.extra)
        return payload

    def to_view_dict(self, *, is_available: bool = True, status_text: str = '') -> dict:
        payload = self.to_meta_dict()
        payload['is_available'] = bool(is_available)
        payload['status_text'] = status_text or ''
        return payload



