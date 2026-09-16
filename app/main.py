"""FastAPI 애플리케이션 엔트리포인트."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes_scans import router as scans_router
from app.core.redaction import RedactingLogFilter


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # 전역 로깅 필터에 RedactingLogFilter 적용
    root_logger = logging.getLogger()
    redact_filter = RedactingLogFilter()
    root_logger.addFilter(redact_filter)

    yield


app = FastAPI(
    title="whereismykey",
    version="0.1.0",
    description="API Key 외부 노출 점검 서비스",
    lifespan=lifespan,
)

app.include_router(scans_router)
