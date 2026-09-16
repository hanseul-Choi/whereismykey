"""인메모리 스캔 잡 레지스트리."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from whereismykey.core.models import JobProgress, JobStatus, ScanJob

if TYPE_CHECKING:
    from whereismykey.core.models import ScanResult


class JobStore:
    """잡 상태를 메모리에 유지하는 저장소 (스레드/비동기 안전)."""

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = asyncio.Lock()

    async def create_job(self, job_id: str) -> ScanJob:
        async with self._lock:
            job = ScanJob(job_id=job_id, status=JobStatus.QUEUED)
            self._jobs[job_id] = job
            return job

    async def get_job(self, job_id: str) -> ScanJob | None:
        async with self._lock:
            return self._jobs.get(job_id)

    async def start_job(self, job_id: str) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.status = JobStatus.RUNNING
                job.started_at = datetime.now(UTC)

    async def update_progress(self, job_id: str, progress: JobProgress) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.progress = progress

    async def add_error(self, job_id: str, error_msg: str) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.errors.append(error_msg)

    async def complete_job(self, job_id: str, result: ScanResult) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.status = JobStatus.COMPLETED
                job.finished_at = datetime.now(UTC)
                job.result = result

    async def fail_job(self, job_id: str, error_msg: str) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.status = JobStatus.FAILED
                job.finished_at = datetime.now(UTC)
                job.errors.append(error_msg)


_DEFAULT_JOB_STORE = JobStore()


def get_job_store() -> JobStore:
    return _DEFAULT_JOB_STORE
