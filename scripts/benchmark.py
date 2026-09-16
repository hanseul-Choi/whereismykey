"""whereismykey 성능 및 정확도 벤치마크 스크립트."""

from __future__ import annotations

import asyncio
import hashlib
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


def run_accuracy_tests() -> dict[str, Any]:
    """정확도(Accuracy, Precision, Recall, False-Positive) 검증."""
    results: dict[str, Any] = {}

    # 1. Exact Match (True Positive) 검증
    tp_count = 0
    total_tp = 50
    for i in range(total_tp):
        doc = f"""
        # Configuration File {i}
        DEBUG = False
        API_TOKEN = "{TARGET_KEY}"
        DATABASE_URL = "postgres://user:pass@localhost:5432/db"
        """
        matches = scan_text(doc, SPEC)
        if (
            len(matches) == 1
            and matches[0].hash_matched
            and TARGET_KEY not in matches[0].snippet
            and "…" in matches[0].snippet
        ):
            tp_count += 1

    results["true_positive_rate"] = (tp_count / total_tp) * 100

    # 2. Pattern Collision (유사 패턴 충돌 시 False Positive 방어) 검증
    collision_defended = 0
    total_collision = 50
    for i in range(total_collision):
        fake_key = f"{PREFIX}{i:032x}{POSTFIX}"
        doc = f'export SECRET="{fake_key}"'
        matches = scan_text(doc, SPEC)
        if len(matches) == 1 and not matches[0].hash_matched:
            collision_defended += 1

    results["collision_defense_rate"] = (collision_defended / total_collision) * 100

    # 3. Boundary Noise (토큰 경계 검사) 검증
    boundary_defended = 0
    total_boundary = 50
    for _ in range(total_boundary):
        wrapped_key = f"prefix{TARGET_KEY}postfix"
        doc = f'const url = "https://example.com/{wrapped_key}";'
        matches = scan_text(doc, SPEC)
        if len(matches) == 0:
            boundary_defended += 1

    results["boundary_defense_rate"] = (boundary_defended / total_boundary) * 100

    # 4. Pure Noise Code (무관한 대량 소스코드) 오탐 검증
    noise_defended = 0
    total_noise = 50
    sample_code = (
        """
    def process_data(items: list[dict]) -> list[str]:
        output = []
        for item in items:
            key = item.get("id", "default_key_prefix")
            val = hashlib.sha256(key.encode()).hexdigest()
            output.append(f"{key}:{val}")
        return output
    """
        * 10
    )
    for _ in range(total_noise):
        matches = scan_text(sample_code, SPEC)
        if len(matches) == 0:
            noise_defended += 1

    results["noise_defense_rate"] = (noise_defended / total_noise) * 100
    return results


def run_speed_throughput_tests() -> dict[str, Any]:
    """속도 및 Throughput 검증."""
    results: dict[str, Any] = {}
    pat = build_pattern(SPEC)

    # 1. 1,000개 문서 배치 스캔 속도 측정
    num_docs = 1000
    doc_template = """
    import os
    import sys

    # Setting up configurations
    AUTH_HEADER = "Bearer sk_other_random_key_value_12345"
    TARGET = "production"
    # End of file
    """
    total_bytes = len(doc_template.encode("utf-8")) * num_docs

    start_time = time.perf_counter()
    for _ in range(num_docs):
        _ = scan_text(doc_template, SPEC, pattern=pat)
    elapsed_time = time.perf_counter() - start_time

    results["batch_1000_time_s"] = elapsed_time
    results["batch_1000_throughput_mb_s"] = (total_bytes / (1024 * 1024)) / elapsed_time
    results["batch_1000_docs_per_sec"] = num_docs / elapsed_time
    results["batch_1000_avg_ms_per_doc"] = (elapsed_time / num_docs) * 1000

    # 2. 5MB 대용량 단일 텍스트 스캔 속도
    chunk = (
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "export KEY=sk_some_other_value_1234567890; "
        "User session token active in system cache. \n"
    ) * 100
    repeats = int((5 * 1024 * 1024) / len(chunk.encode("utf-8")))
    large_text = chunk * repeats + f"\nSECRET_EXPOSED = '{TARGET_KEY}'\n"
    large_bytes = len(large_text.encode("utf-8"))

    start_time = time.perf_counter()
    matches = scan_text(large_text, SPEC, pattern=pat)
    large_elapsed = time.perf_counter() - start_time

    assert len(matches) >= 1
    results["large_5mb_size_mb"] = large_bytes / (1024 * 1024)
    results["large_5mb_time_s"] = large_elapsed
    results["large_5mb_throughput_mb_s"] = (large_bytes / (1024 * 1024)) / large_elapsed

    return results


class BenchmarkMockSource(SearchSource):
    def __init__(self, name: str, findings: list[Finding]) -> None:
        self._name = name
        self._findings = findings

    @property
    def name(self) -> str:
        return self._name

    @property
    def stage(self) -> Stage:
        return Stage.GITHUB

    async def search_and_match(self, spec, options: ScanOptions) -> list[Finding]:
        await asyncio.sleep(0.005)
        return self._findings


async def run_e2e_pipeline_benchmark() -> dict[str, Any]:
    """스캔 엔진 E2E 비동기 파이프라인 지연시간 측정 (10개 동시 소스)."""
    job_store = JobStore()
    engine = ScanEngine(job_store=job_store)

    findings = [
        Finding(
            confidence=Confidence.CONFIRMED,
            severity=Severity.CRITICAL,
            stage=Stage.GITHUB,
            source="benchmark_source",
            url="https://github.com/test/repo",
            snippet="sk_live_…_a1b2c3d",
        )
    ]
    sources = [BenchmarkMockSource(f"src_{i}", findings) for i in range(10)]

    job_id = "bench-job-1"
    await job_store.create_job(job_id)

    start_time = time.perf_counter()
    await engine.run_scan(
        job_id=job_id,
        spec=SPEC,
        stages=[Stage.GITHUB],
        options=ScanOptions(),
        sources=sources,
    )
    elapsed = time.perf_counter() - start_time

    job = await job_store.get_job(job_id)
    assert job is not None
    assert job.result is not None
    assert job.result.verdict == Verdict.EXPOSED

    return {
        "e2e_pipeline_time_ms": elapsed * 1000,
        "sources_processed": 10,
        "final_verdict": job.result.verdict.value,
    }


def main() -> None:
    print("==========================================================")
    print("       whereismykey 성능 & 정확도 벤치마크 시작")
    print("==========================================================")

    # 1. 정확도 테스트
    print("\n[1] 정확도 및 오탐 방지 검증 (Accuracy & False Positive Test)")
    acc = run_accuracy_tests()
    print(f"  - 정답 키 탐지율 (Recall)               : {acc['true_positive_rate']:.1f}%")
    print(f"  - 해시 충돌 방어율 (False Positive = 0)  : {acc['collision_defense_rate']:.1f}%")
    print(f"  - 토큰 경계 노이즈 차단율 (Boundary)    : {acc['boundary_defense_rate']:.1f}%")
    print(f"  - 일반 코드 노이즈 오탐 차단율          : {acc['noise_defense_rate']:.1f}%")

    # 2. 속도 및 처리량 테스트
    print("\n[2] 처리 속도 및 Throughput 검증 (Speed & Throughput)")
    spd = run_speed_throughput_tests()
    t_1000 = spd["batch_1000_time_s"] * 1000
    avg_1000 = spd["batch_1000_avg_ms_per_doc"]
    dps = spd["batch_1000_docs_per_sec"]
    tp_1000 = spd["batch_1000_throughput_mb_s"]
    t_5mb = spd["large_5mb_time_s"] * 1000
    tp_5mb = spd["large_5mb_throughput_mb_s"]

    print(f"  - 1,000개 문서 스캔 시간 : {t_1000:.2f} ms")
    print(f"  - 문서당 평균 처리 시간  : {avg_1000:.3f} ms/doc")
    print(f"  - 초당 문서 처리량       : {dps:,.0f} docs/s")
    print(f"  - 배치 처리 Throughput   : {tp_1000:.2f} MB/s")
    print(f"  - 5MB 텍스트 스캔 시간   : {t_5mb:.2f} ms")
    print(f"  - 대용량 텍스트 Throughput: {tp_5mb:.2f} MB/s")

    # 3. 비동기 E2E 파이프라인 테스트
    print("\n[3] 비동기 오케스트레이션 E2E 파이프라인 (End-to-End Pipeline)")
    e2e = asyncio.run(run_e2e_pipeline_benchmark())
    print(f"  - 10개 소스 병렬 수집 + 매칭 + 리포트   : {e2e['e2e_pipeline_time_ms']:.2f} ms")
    print(f"  - 최종 판정 (Verdict)                   : {e2e['final_verdict']}")

    print("\n==========================================================")
    print("                    벤치마크 완료")
    print("==========================================================")


if __name__ == "__main__":
    main()
