from dataclasses import dataclass, field


@dataclass
class BackgroundJobMessage:
    status: int = 1
    text: str = ''
    eof: int = 0
    time: str = ''

    @classmethod
    def from_dict(cls, payload: dict | None):
        if not isinstance(payload, dict):
            return cls()

        return cls(
            status=int(payload.get('status', 1) or 1),
            text=str(payload.get('text') or ''),
            eof=int(payload.get('eof', 0) or 0),
            time=str(payload.get('time') or ''),
        )

    def to_dict(self) -> dict:
        return {
            'status': self.status,
            'text': self.text,
            'eof': self.eof,
            'time': self.time,
        }


@dataclass
class BackgroundJobFileRef:
    artifact_id: str = ''
    artifact_type: str = ''
    category: str = ''
    hostname: str = ''
    client_id: str = ''
    original_name: str = ''
    stored_name: str = ''
    size: int = 0
    created_at: str = ''
    source_type: str = ''
    download_url: str = ''
    raw_url: str = ''
    preview_url: str = ''
    is_available: bool = True
    status_text: str = ''

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
            original_name=payload.get('original_name', ''),
            stored_name=payload.get('stored_name', ''),
            size=int(payload.get('size', 0) or 0),
            created_at=payload.get('created_at', ''),
            source_type=payload.get('source_type', ''),
            download_url=payload.get('download_url', ''),
            raw_url=payload.get('raw_url', ''),
            preview_url=payload.get('preview_url', ''),
            is_available=bool(payload.get('is_available', True)),
            status_text=payload.get('status_text', ''),
        )

    def to_dict(self) -> dict:
        return {
            'artifact_id': self.artifact_id,
            'artifact_type': self.artifact_type,
            'category': self.category,
            'hostname': self.hostname,
            'client_id': self.client_id,
            'original_name': self.original_name,
            'stored_name': self.stored_name,
            'size': self.size,
            'created_at': self.created_at,
            'source_type': self.source_type,
            'download_url': self.download_url,
            'raw_url': self.raw_url,
            'preview_url': self.preview_url,
            'is_available': self.is_available,
            'status_text': self.status_text,
        }


@dataclass
class BackgroundJobState:
    job_id: str = ''
    client_id: str = ''
    job_name: str = ''
    job_key: str = ''
    display_name: str = ''
    thread_name: str = ''
    command_id: int | None = None
    state: str = 'unknown'
    created_at: str = ''
    started_at: str = ''
    stopped_at: str = ''
    updated_at: str = ''
    last_message: str = ''
    message_count: int = 0
    file_count: int = 0
    messages: list[dict] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: dict | None):
        if not isinstance(payload, dict):
            return cls()

        return cls(
            job_id=payload.get('job_id', ''),
            client_id=payload.get('client_id', ''),
            job_name=payload.get('job_name', ''),
            job_key=payload.get('job_key', ''),
            display_name=payload.get('display_name', ''),
            thread_name=payload.get('thread_name', ''),
            command_id=payload.get('command_id'),
            state=payload.get('state', 'unknown'),
            created_at=payload.get('created_at', ''),
            started_at=payload.get('started_at', ''),
            stopped_at=payload.get('stopped_at', ''),
            updated_at=payload.get('updated_at', ''),
            last_message=payload.get('last_message', ''),
            message_count=int(payload.get('message_count', 0) or 0),
            file_count=int(payload.get('file_count', 0) or 0),
            messages=list(payload.get('messages') or []),
            files=list(payload.get('files') or []),
        )

    def to_dict(self) -> dict:
        return {
            'job_id': self.job_id,
            'client_id': self.client_id,
            'job_name': self.job_name,
            'job_key': self.job_key,
            'display_name': self.display_name,
            'thread_name': self.thread_name,
            'command_id': self.command_id,
            'state': self.state,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'stopped_at': self.stopped_at,
            'updated_at': self.updated_at,
            'last_message': self.last_message,
            'message_count': self.message_count,
            'file_count': self.file_count,
            'messages': list(self.messages),
            'files': list(self.files),
        }