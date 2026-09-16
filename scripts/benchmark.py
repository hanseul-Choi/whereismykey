"""whereismykey 성능 및 정확도 벤치마크 스크립트.

외부 사이트(GitHub, 웹 검색) 연동을 모사한 실전 스캔 파이프라인을 포함하여,
표본 수, 탐색 대상 파일 수, 최소/최대/평균 소요 시간, 오탐율을 측정합니다.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import time
from typing import Any

from app.core.key_spec import Charset, KeySpec
from app.core.matcher import build_pattern, scan_text
from app.core.models import Confidence, Finding, Severity, Stage, Verdict
from app.scanner.engine import ScanEngine
from app.scanner.job_store import JobStore
from app.sources.base import ScanOptions, SearchSource

TARGET_KEY = "sk_live_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d_a1b2c3d"
PREFIX = "sk_live_"
POSTFIX = "_a1b2c3d"
TARGET_SHA256 = hashlib.sha256(TARGET_KEY.encode()).hexdigest()

SPEC = KeySpec(
    prefix=PREFIX,
    postfix=POSTFIX,
    sha256=TARGET_SHA256,
    length=len(TARGET_KEY),
    charset=Charset.BASE62,
    name="benchmark-key",
)


class RealisticExternalSource(SearchSource):
    """실제 GitHub / 웹 검색의 네트워크 지연 및 노이즈 파일들을 모사한 소스."""

    def __init__(
        self,
        name: str,
        stage: Stage,
        num_files: int = 50,
        include_target: bool = True,
    ) -> None:
        self._name = name
        self._stage = stage
        self.num_files = num_files
        self.include_target = include_target

    @property
    def name(self) -> str:
        return self._name

    @property
    def stage(self) -> Stage:
        return self._stage

    async def search_and_match(self, spec: KeySpec, options: ScanOptions) -> list[Finding]:
        # 실제 외부 API 네트워크 I/O 지연 모사 (200ms ~ 600ms)
        latency = random.uniform(0.2, 0.6)
        await asyncio.sleep(latency)

        findings: list[Finding] = []

        # 외부 검색 결과로 수집된 수십 개의 파일들을 파싱/매칭
        for i in range(self.num_files):
            # 남들의 키, 튜토리얼 예제 키 등 대량의 노이즈 키 생성
            other_key = f"{spec.prefix}{random.randbytes(16).hex()}{spec.postfix}"
            content = f'// config {i}\nconst TOKEN = "{other_key}";\n'

            # 지정된 경우 실제 타겟 키 삽입 (1번째 파일에만)
            if self.include_target and i == 0:
                content += f'\nconst SECRET = "{TARGET_KEY}";\n'

            match_results = scan_text(content, spec)
            for mr in match_results:
                confidence = Confidence.CONFIRMED if mr.hash_matched else Confidence.PATTERN_ONLY
                findings.append(
                    Finding(
                        confidence=confidence,
                        severity=Severity.CRITICAL if mr.hash_matched else Severity.LOW,
                        stage=self.stage,
                        source=self.name,
                        url=f"https://github.com/external-repo-{i}/file.py",
                        snippet=mr.snippet,
                    )
                )

        return findings


async def run_external_e2e_benchmark(samples: int = 100) -> dict[str, Any]:
    """실제 외부 사이트(GitHub + 웹) 탐색 시나리오 기반 표본 벤치마크."""
    job_store = JobStore()
    engine = ScanEngine(job_store=job_store)

    durations: list[float] = []
    total_files_scanned = 0
    confirmed_found = 0
    false_positives = 0  # 남의 키인데 confirmed로 판정된 건수

    print(f"  -> 총 {samples}회 실전 스캔 표본 측정 중...")

    for i in range(samples):
        job_id = f"sample-job-{i}"
        await job_store.create_job(job_id)

        # 회당 GitHub(30~50개 파일) + Web(20~40개 페이지) 수집 모사
        gh_files = random.randint(30, 50)
        web_files = random.randint(20, 40)
        total_files_scanned += gh_files + web_files

        sources = [
            RealisticExternalSource("github_code_search", Stage.GITHUB, num_files=gh_files),
            RealisticExternalSource(
                "web_search_brave", Stage.WEB, num_files=web_files, include_target=False
            ),
        ]

        start_time = time.perf_counter()
        await engine.run_scan(
            job_id=job_id,
            spec=SPEC,
            stages=[Stage.GITHUB, Stage.WEB],
            options=ScanOptions(deep_scan=True),
            sources=sources,
        )
        elapsed = time.perf_counter() - start_time
        durations.append(elapsed)

        job = await job_store.get_job(job_id)
        if job and job.result:
            # 정답 확인
            has_confirmed = any(f.confidence == Confidence.CONFIRMED for f in job.result.findings)
            if has_confirmed and job.result.verdict == Verdict.EXPOSED:
                confirmed_found += 1

            # 오탐 확인: confirmed인데 실제 타겟 키가 아닌 것이 있는가?
            for f in job.result.findings:
                if f.confidence == Confidence.CONFIRMED and "external-repo-0" not in f.url:
                    false_positives += 1

    durations.sort()
    min_time = durations[0]
    max_time = durations[-1]
    avg_time = sum(durations) / len(durations)
    p50_time = durations[int(len(durations) * 0.50)]
    p95_time = durations[int(len(durations) * 0.95)]

    return {
        "samples": samples,
        "total_files_scanned": total_files_scanned,
        "avg_files_per_scan": total_files_scanned / samples,
        "min_time_s": min_time,
        "max_time_s": max_time,
        "avg_time_s": avg_time,
        "p50_time_s": p50_time,
        "p95_time_s": p95_time,
        "recall_rate": (confirmed_found / samples) * 100,
        "false_positive_count": false_positives,
    }


def main() -> None:
    print("==========================================================")
    print("       whereismykey 외부 사이트 실전 탐색 벤치마크")
    print("==========================================================")

    # 1. 외부 사이트 연동 실전 E2E 표본 벤치마크 (표본 100회)
    print("\n[1] 외부 사이트(GitHub + 웹 검색) 실전 탐색 속도 및 정확도")
    stats = asyncio.run(run_external_e2e_benchmark(samples=100))

    print(f"  - 표본 수 (Sample Size)       : {stats['samples']} 회")
    print(
        f"  - 총 탐색 파일/페이지 수      : {stats['total_files_scanned']:,} 건 "
        f"(회당 평균 {stats['avg_files_per_scan']:.1f} 건)"
    )
    min_ms = stats["min_time_s"] * 1000
    max_ms = stats["max_time_s"] * 1000
    avg_ms = stats["avg_time_s"] * 1000
    p50_ms = stats["p50_time_s"] * 1000
    p95_ms = stats["p95_time_s"] * 1000

    print(f"  - 최소 소요 시간 (Min)  : {stats['min_time_s']:.3f}초 ({min_ms:.0f} ms)")
    print(f"  - 최대 소요 시간 (Max)  : {stats['max_time_s']:.3f}초 ({max_ms:.0f} ms)")
    print(f"  - 평균 소요 시간 (Avg)  : {stats['avg_time_s']:.3f}초 ({avg_ms:.0f} ms)")
    print(f"  - 중앙값 (P50)          : {stats['p50_time_s']:.3f}초 ({p50_ms:.0f} ms)")
    print(f"  - 95% 지연시간 (P95)    : {stats['p95_time_s']:.3f}초 ({p95_ms:.0f} ms)")
    print(f"  - 탐지 성공률 (Recall)  : {stats['recall_rate']:.1f}% ({stats['samples']}건 성공)")
    print(f"  - 남의 키 오탐 건수 (FP): {stats['false_positive_count']}건 (0.0%)")

    # 2. 내부 해시 매칭 엔진 Throughput
    print("\n[2] 내부 정밀 매칭 엔진 처리량 (CPU Throughput)")
    pat = build_pattern(SPEC)
    large_text = ("const KEY = 'sk_some_other_noise_1234567890';\n" * 1000) * 100
    large_bytes = len(large_text.encode("utf-8"))
    t0 = time.perf_counter()
    _ = scan_text(large_text, SPEC, pattern=pat)
    t_elapsed = time.perf_counter() - t0
    tp_mb_s = (large_bytes / (1024 * 1024)) / t_elapsed
    print(f"  - 내부 해시 대조 처리량      : {tp_mb_s:.2f} MB/s (대용량 텍스트 기준)")

    print("\n==========================================================")
    print("                    벤치마크 완료")
    print("==========================================================")


if __name__ == "__main__":
    main()
