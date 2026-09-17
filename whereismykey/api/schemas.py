"""API 요청/응답 Pydantic 스키마."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from whereismykey.core.key_spec import Charset, KeySpec
from whereismykey.core.models import Confidence, JobStatus, Severity, Stage, Verdict


class KeySpecSchema(BaseModel):
    """키 명세 요청 스키마."""

    prefix: str
    postfix: str
    sha256: str
    length: int | None = None
    charset: Charset | None = None
    custom_charset: str | None = None
    name: str | None = None
    key_type: str = "custom"

    def to_domain(self) -> KeySpec:
        return KeySpec(
            prefix=self.prefix,
            postfix=self.postfix,
            sha256=self.sha256,
            length=self.length,
            charset=self.charset,
            custom_charset=self.custom_charset,
            name=self.name,
            key_type=self.key_type,
        )


class ScanOptionsSchema(BaseModel):
    """스캔 실행 옵션."""

    max_results_per_source: int = 100
    include_pattern_only: bool = True
    fetch_timeout_s: float = 10.0
    deep_scan: bool = True
    qualifiers: list[str] | None = None
    crawl_urls: list[str] | None = None
    crawl_max_depth: int = 1


class ScanCreateRequest(BaseModel):
    """스캔 생성 요청."""

    key_spec: KeySpecSchema
    stages: list[Stage] = Field(default_factory=lambda: [Stage.GITHUB, Stage.WEB])
    options: ScanOptionsSchema = Field(default_factory=ScanOptionsSchema)


class ScanCreateResponse(BaseModel):
    """스캔 접수 응답 (202 Accepted)."""

    job_id: str
    status: JobStatus = JobStatus.QUEUED
    poll_url: str


class FindingSchema(BaseModel):
    """발견 항목 응답."""

    model_config = ConfigDict(from_attributes=True)

    confidence: Confidence
    severity: Severity
    stage: Stage
    source: str
    url: str
    repo: str | None = None
    path: str | None = None
    line: int | None = None
    snippet: str = ""


class JobProgressSchema(BaseModel):
    """스캔 진행률 응답."""

    model_config = ConfigDict(from_attributes=True)

    stage: Stage | None = None
    sources_done: int = 0
    sources_total: int = 0


class ScanResultSchema(BaseModel):
    """최종 스캔 결과 응답."""

    model_config = ConfigDict(from_attributes=True)

    verdict: Verdict
    key_name: str | None = None
    key_redacted: str
    findings: list[FindingSchema] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    takedown_message_template: str = ""


class ScanJobResponse(BaseModel):
    """스캔 잡 상세 상태 응답."""

    model_config = ConfigDict(from_attributes=True)

    job_id: str
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    progress: JobProgressSchema = Field(default_factory=JobProgressSchema)
    result: ScanResultSchema | None = None
    errors: list[str] = Field(default_factory=list)
