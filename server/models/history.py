from dataclasses import dataclass, field
from typing import Any


@dataclass
class HistoryOutputRecord:
    seq: int = 0
    status: int = 1
    text: str = ''
    time: str = ''
    eof: int = 0

    @classmethod
    def from_dict(cls, payload: dict | None):
        if not isinstance(payload, dict):
            return cls()
        return cls(
            seq=int(payload.get('seq', 0) or 0),
            status=int(payload.get('status', 1) or 1),
            text=str(payload.get('text') or ''),
            time=str(payload.get('time') or ''),
            eof=int(payload.get('eof', 0) or 0),
        )

    def to_dict(self) -> dict:
        return {
            'seq': self.seq,
            'status': self.status,
            'text': self.text,
            'time': self.time,
            'eof': self.eof,
        }


@dataclass
class HistoryFileRef:
    artifact_id: str = ''
    artifact_type: str = ''
    category: str = ''
    hostname: str = ''
    client_id: str = ''
    original_name: str = ''
    stored_name: str = ''
    saved_path: str = ''
    size: int = 0
    created_at: str = ''
    download_url: str = ''
    raw_url: str = ''
    preview_url: str = ''
    source_type: str = ''
    related_path: str = ''
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
            saved_path=payload.get('saved_path', ''),
            size=int(payload.get('size', 0) or 0),
            created_at=payload.get('created_at', ''),
            download_url=payload.get('download_url', ''),
            raw_url=payload.get('raw_url', ''),
            preview_url=payload.get('preview_url', ''),
            source_type=payload.get('source_type', ''),
            related_path=payload.get('related_path', ''),
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
            'saved_path': self.saved_path,
            'size': self.size,
            'created_at': self.created_at,
            'download_url': self.download_url,
            'raw_url': self.raw_url,
            'preview_url': self.preview_url,
            'source_type': self.source_type,
            'related_path': self.related_path,
            'is_available': self.is_available,
            'status_text': self.status_text,
        }


@dataclass
class HistoryEntry:
    entry_id: str = ''
    time: str = ''
    started_at: str = ''
    finished_at: str = ''
    duration_ms: int = 0

    command: str = ''
    source: str = ''
    status: str = 'running'
    final_status: str = ''

    hostname: str = 'unknown_host'
    client_id: str = ''
    addr: str = ''
    cwd_start: str = ''
    cwd_end: str = ''

    has_output: bool = False
    output_summary: str = ''
    output_line_count: int = 0
    output_chunk_count: int = 0
    output_char_count: int = 0
    output_stored_char_count: int = 0
    output_truncated: bool = False
    output_record_seq: int = 0
    output_records: list[dict] = field(default_factory=list)

    has_files: bool = False
    file_count: int = 0
    files: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: dict | None):
        if not isinstance(payload, dict):
            return cls()

        return cls(
            entry_id=payload.get('entry_id', ''),
            time=payload.get('time', ''),
            started_at=payload.get('started_at', ''),
            finished_at=payload.get('finished_at', ''),
            duration_ms=int(payload.get('duration_ms', 0) or 0),
            command=payload.get('command', ''),
            source=payload.get('source', ''),
            status=payload.get('status', 'running'),
            final_status=payload.get('final_status', ''),
            hostname=payload.get('hostname', 'unknown_host'),
            client_id=payload.get('client_id', ''),
            addr=payload.get('addr', ''),
            cwd_start=payload.get('cwd_start', ''),
            cwd_end=payload.get('cwd_end', ''),
            has_output=bool(payload.get('has_output', False)),
            output_summary=payload.get('output_summary', ''),
            output_line_count=int(payload.get('output_line_count', 0) or 0),
            output_chunk_count=int(payload.get('output_chunk_count', 0) or 0),
            output_char_count=int(payload.get('output_char_count', 0) or 0),
            output_stored_char_count=int(payload.get('output_stored_char_count', 0) or 0),
            output_truncated=bool(payload.get('output_truncated', False)),
            output_record_seq=int(payload.get('output_record_seq', 0) or 0),
            output_records=list(payload.get('output_records') or []),
            has_files=bool(payload.get('has_files', False)),
            file_count=int(payload.get('file_count', 0) or 0),
            files=list(payload.get('files') or []),
        )

    def to_dict(self) -> dict:
        return {
            'entry_id': self.entry_id,
            'time': self.time,
            'started_at': self.started_at,
            'finished_at': self.finished_at,
            'duration_ms': self.duration_ms,
            'command': self.command,
            'source': self.source,
            'status': self.status,
            'final_status': self.final_status,
            'hostname': self.hostname,
            'client_id': self.client_id,
            'addr': self.addr,
            'cwd_start': self.cwd_start,
            'cwd_end': self.cwd_end,
            'has_output': self.has_output,
            'output_summary': self.output_summary,
            'output_line_count': self.output_line_count,
            'output_chunk_count': self.output_chunk_count,
            'output_char_count': self.output_char_count,
            'output_stored_char_count': self.output_stored_char_count,
            'output_truncated': self.output_truncated,
            'output_record_seq': self.output_record_seq,
            'output_records': list(self.output_records),
            'has_files': self.has_files,
            'file_count': self.file_count,
            'files': list(self.files),
        }


