"""스캔 엔진 및 잡 스토어 통합 오케스트레이션 테스트."""

from __future__ import annotations

import pytest
from app.core.models import (
    Confidence,
    Finding,
    JobStatus,
    Severity,
    Stage,
    Verdict,
)
from app.scanner.engine import ScanEngine
from app.scanner.job_store import JobStore
from app.sources.base import ScanOptions, SearchSource


class MockSource(SearchSource):
    def __init__(
        self,
        name: str,
        stage: Stage,
        findings: list[Finding] | None = None,
        should_fail: bool = False,
    ) -> None:
        self._name = name
        self._stage = stage
        self._findings = findings or []
        self._should_fail = should_fail

    @property
    def name(self) -> str:
        return self._name

    @property
    def stage(self) -> Stage:
        return self._stage

    async def search_and_match(self, spec, options: ScanOptions) -> list[Finding]:
        if self._should_fail:
            raise RuntimeError(f"Source {self._name} failed")
        return self._findings


@pytest.mark.asyncio
async def test_engine_successful_exposed_scan(key_spec_no_length) -> None:
    job_store = JobStore()
    engine = ScanEngine(job_store=job_store)

    job_id = "test-job-1"
    await job_store.create_job(job_id)

    confirmed_finding = Finding(
        confidence=Confidence.CONFIRMED,
        severity=Severity.CRITICAL,
        stage=Stage.GITHUB,
        source="mock_github",
        url="https://github.com/test/repo/file.py",
        snippet="sk_live…a1b2c3d",
    )

    sources = [
        MockSource("mock_github", Stage.GITHUB, findings=[confirmed_finding]),
        MockSource("mock_web", Stage.WEB, findings=[]),
    ]

    await engine.run_scan(
        job_id=job_id,
        spec=key_spec_no_length,
        stages=[Stage.GITHUB, Stage.WEB],
        options=ScanOptions(),
        sources=sources,
    )

    job = await job_store.get_job(job_id)
    assert job is not None
    assert job.status == JobStatus.COMPLETED
    assert job.started_at is not None
    assert job.finished_at is not None
    assert job.progress.sources_done == 2
    assert job.progress.sources_total == 2
    assert job.result is not None
    assert job.result.verdict == Verdict.EXPOSED
    assert len(job.result.findings) == 1
    assert "https://github.com/test/repo/file.py" in job.result.takedown_message_template
    assert len(job.result.recommendations) > 0


@pytest.mark.asyncio
async def test_engine_source_error_handling(key_spec_no_length) -> None:
    job_store = JobStore()
    engine = ScanEngine(job_store=job_store)

    job_id = "test-job-error"
    await job_store.create_job(job_id)

    sources = [
        MockSource("mock_github", Stage.GITHUB, should_fail=True),
    ]

    await engine.run_scan(
        job_id=job_id,
        spec=key_spec_no_length,
        stages=[Stage.GITHUB],
        options=ScanOptions(),
        sources=sources,
    )

    job = await job_store.get_job(job_id)
    assert job is not None
    assert job.status == JobStatus.COMPLETED
    assert len(job.errors) == 1
    assert "Source mock_github failed" in job.errors[0]
    assert job.result is not None
    assert job.result.verdict == Verdict.INCONCLUSIVE


@pytest.mark.asyncio
async def test_engine_include_pattern_only_false(key_spec_no_length) -> None:
    job_store = JobStore()
    engine = ScanEngine(job_store=job_store)

    job_id = "test-job-filter"
    await job_store.create_job(job_id)

    pattern_finding = Finding(
        confidence=Confidence.PATTERN_ONLY,
        severity=Severity.LOW,
        stage=Stage.WEB,
        source="mock_web",
        url="https://example.com",
        snippet="snippet",
    )

    sources = [MockSource("mock_web", Stage.WEB, findings=[pattern_finding])]

    await engine.run_scan(
        job_id=job_id,
        spec=key_spec_no_length,
        stages=[Stage.WEB],
        options=ScanOptions(include_pattern_only=False),
        sources=sources,
    )

    job = await job_store.get_job(job_id)
    assert job is not None
    assert job.result is not None
    assert job.result.verdict == Verdict.INCONCLUSIVE  # pattern_only가 있었으므로
    assert len(job.result.findings) == 0  # include_pattern_only=False 이므로 결과 목록에서는 제외
