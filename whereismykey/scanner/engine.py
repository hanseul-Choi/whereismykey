"""스캔 실행 오케스트레이션 엔진."""

from __future__ import annotations

import asyncio
import logging

from whereismykey.config import Settings, get_settings
from whereismykey.core.key_spec import KeySpec
from whereismykey.core.models import Finding, JobProgress, Stage
from whereismykey.report.builder import build_scan_result
from whereismykey.scanner.job_store import JobStore, get_job_store
from whereismykey.scanner.stages import create_sources_for_stages
from whereismykey.sources.base import ScanOptions, SearchSource

logger = logging.getLogger(__name__)


class ScanEngine:
    """스캔 잡들을 비동기 큐/세마포어로 실행하고 결과를 집합하는 엔진."""

    def __init__(
        self,
        job_store: JobStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.job_store = job_store or get_job_store()
        self.settings = settings or get_settings()
        self._semaphore = asyncio.Semaphore(self.settings.max_concurrent_jobs)

    async def run_scan(
        self,
        job_id: str,
        spec: KeySpec,
        stages: list[Stage],
        options: ScanOptions,
        sources: list[SearchSource] | None = None,
    ) -> None:
        """백그라운드에서 단일 스캔 잡을 실행."""
        try:
            async with self._semaphore:
                await self.job_store.start_job(job_id)

                scan_sources = (
                    sources
                    if sources is not None
                    else create_sources_for_stages(stages, self.settings)
                )
                sources_total = len(scan_sources)
                sources_done = 0
                all_findings: list[Finding] = []
                errors: list[str] = []

                if sources_total == 0:
                    await self.job_store.update_progress(
                        job_id,
                        JobProgress(stage=None, sources_done=0, sources_total=0),
                    )
                else:
                    for source in scan_sources:
                        await self.job_store.update_progress(
                            job_id,
                            JobProgress(
                                stage=source.stage,
                                sources_done=sources_done,
                                sources_total=sources_total,
                            ),
                        )
                        try:
                            findings = await source.search_and_match(spec, options)
                            all_findings.extend(findings)
                        except Exception as e:
                            err_msg = f"[{source.name}] {e}"
                            logger.error("Error running source %s: %s", source.name, e)
                            errors.append(err_msg)
                            await self.job_store.add_error(job_id, err_msg)
                        finally:
                            sources_done += 1
                            await self.job_store.update_progress(
                                job_id,
                                JobProgress(
                                    stage=source.stage,
                                    sources_done=sources_done,
                                    sources_total=sources_total,
                                ),
                            )

                result = build_scan_result(spec, all_findings, errors, options)
                await self.job_store.complete_job(job_id, result)

        except Exception as e:
            logger.exception("Unexpected error in scan job %s: %s", job_id, e)
            await self.job_store.fail_job(job_id, f"Job failed unexpectedly: {e}")


_DEFAULT_ENGINE: ScanEngine | None = None


def get_scan_engine() -> ScanEngine:
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = ScanEngine()
    return _DEFAULT_ENGINE
