"""스캔 관련 FastAPI 라우트 및 인증."""

from __future__ import annotations

import asyncio
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from app.api.schemas import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanJobResponse,
)
from app.config import Settings, get_settings
from app.core.key_spec import KeySpecError
from app.scanner.engine import ScanEngine, get_scan_engine
from app.scanner.job_store import JobStore, get_job_store
from app.sources.base import ScanOptions

router = APIRouter()

# RUF006: 실행 중인 비동기 태스크 참조 유지 (가비지 컬렉션 방지)
_background_tasks: set[asyncio.Task[None]] = set()


def verify_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,  # type: ignore[assignment]
) -> None:
    """API Key 인증 의존성. service_api_key 미설정 시 통과."""
    if settings.service_api_key is not None and (
        not x_api_key or x_api_key != settings.service_api_key
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


@router.get("/healthz", tags=["health"])
async def healthz() -> dict[str, str]:
    """서비스 상태 점검."""
    return {"status": "ok"}


@router.post(
    "/scans",
    response_model=ScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_api_key)],
    tags=["scans"],
)
async def create_scan(
    request: ScanCreateRequest,
    job_store: Annotated[JobStore, Depends(get_job_store)],
    engine: Annotated[ScanEngine, Depends(get_scan_engine)],
) -> ScanCreateResponse:
    """새로운 비동기 스캔 잡을 생성하고 시작."""
    try:
        spec = request.key_spec.to_domain()
    except KeySpecError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(e),
        ) from e

    job_id = str(uuid.uuid4())
    job = await job_store.create_job(job_id)

    options = ScanOptions(
        max_results_per_source=request.options.max_results_per_source,
        include_pattern_only=request.options.include_pattern_only,
        fetch_timeout_s=request.options.fetch_timeout_s,
        deep_scan=request.options.deep_scan,
        qualifiers=request.options.qualifiers,
    )

    # 백그라운드 태스크로 스캔 오케스트레이션 실행 (태스크 참조 보관)
    task = asyncio.create_task(engine.run_scan(job_id, spec, request.stages, options))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    return ScanCreateResponse(
        job_id=job.job_id,
        status=job.status,
        poll_url=f"/scans/{job.job_id}",
    )


@router.get(
    "/scans/{job_id}",
    response_model=ScanJobResponse,
    dependencies=[Depends(verify_api_key)],
    tags=["scans"],
)
async def get_scan(
    job_id: str,
    job_store: Annotated[JobStore, Depends(get_job_store)],
) -> ScanJobResponse:
    """스캔 잡 상태 및 결과 조회."""
    job = await job_store.get_job(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan job not found",
        )
    return ScanJobResponse.model_validate(job)
