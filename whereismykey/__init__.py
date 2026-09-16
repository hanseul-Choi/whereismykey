"""whereismykey — API Key 외부 노출 점검 라이브러리 및 서비스.

평문 키를 저장하거나 전송하지 않고, prefix, postfix, SHA-256 해시만을 활용하여
공개 저장소(GitHub) 및 외부 웹에 키가 노출되었는지 안전하게 점검합니다.
"""

from __future__ import annotations

from whereismykey.core.key_spec import Charset, KeySpec, KeySpecError
from whereismykey.core.matcher import scan_text
from whereismykey.core.models import (
    Confidence,
    Finding,
    JobProgress,
    JobStatus,
    ScanJob,
    ScanResult,
    Severity,
    Stage,
    Verdict,
)
from whereismykey.core.redaction import redact_key
from whereismykey.sdk import scan, scan_async
from whereismykey.sources.base import ScanOptions

__version__ = "0.1.0"

__all__ = [
    "Charset",
    "Confidence",
    "Finding",
    "JobProgress",
    "JobStatus",
    "KeySpec",
    "KeySpecError",
    "ScanJob",
    "ScanOptions",
    "ScanResult",
    "Severity",
    "Stage",
    "Verdict",
    "__version__",
    "redact_key",
    "scan",
    "scan_async",
    "scan_text",
]
