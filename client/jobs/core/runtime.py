from dataclasses import dataclass, field
from datetime import datetime
from threading import Thread
from typing import Optional

from client.jobs.core.job import Job


@dataclass
class JobRuntime:
    """
    运行中的任务记录
    """
    job_key: str
    job_instance: Job
    thread: Thread
    created_at: datetime = field(default_factory=datetime.now)
    stopped_at: Optional[datetime] = None

    @property
    def is_alive(self) -> bool:
        return self.thread.is_alive()

    @property
    def display_name(self) -> str:
        return f'{self.job_key}#{self.job_instance.job_id[:8]}'

    def mark_stopped(self):
        self.stopped_at = datetime.now()