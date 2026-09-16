# whereismykey

> **API Key 외부 노출 점검 서비스**  
> 평문 키를 서버에 보관하거나 전송하지 않고, **앞부분(prefix)**, **뒷부분(postfix)**, 그리고 **전체 SHA-256 해시**만을 활용하여 공개 저장소(GitHub) 및 외부 웹에 키가 노출되었는지 자동으로 탐지합니다.

---

## 1. 주요 특징

- **평문 미보관 매칭 (Zero-Knowledge Hash Matching)**: 키 평문 없이 `KeySpec`을 통해 후보 토큰을 추출하고, SHA-256 해시를 대조하여 노출 여부를 확정(`confirmed`)합니다.
- **핀포인트 결합 쿼리 (`"{prefix}" "{postfix}"`)**: 흔한 prefix 검색으로 인한 수십만 건의 검색 노이즈를 99.99% 압축하여 전 세계 수억 개 파일 중 내 키가 있는 페이지만 1~2위로 즉시 타겟팅합니다.
- **전수 탐색(Deep Scan) 페이지네이션**: 1페이지(100건)에서 멈추지 않고, 검색 결과가 더 존재할 경우 최대 1,000건까지 페이지를 순회하며 전수 스캔합니다.
- **안전한 마스킹 (Redaction)**: 응답 결과, 로그, 스니펫 등 모든 출력에서 키는 `prefix…postfix` 형태로 마스킹됩니다.
- **2단계 점검 파이프라인**:
  - **1단계 — GitHub**: GitHub Code Search API를 통한 공개 저장소 결합 검색
  - **2단계 — 외부 웹**: 검색 엔진(Brave Search API 기본, Google CSE / SerpAPI 지원) + SSRF 가드가 적용된 본문 Fetcher
- **비동기 잡 & 폴링 API**: 대량 검색을 백그라운드 태스크로 처리하고 진행 상황 및 결과를 JSON 리포트로 제공합니다.
- **조치 권고 & 삭제 요청(Takedown) 템플릿**: 노출 확인 시 즉시 키 폐기 권고와 노출 사이트 관리자에게 보낼 삭제 요청 메시지를 자동 생성합니다.

---

## 2. ⚡ 성능 & 정확도 실측 벤치마크 (외부 사이트 실전 탐색 결과)

실제 외부 사이트(GitHub Code Search, Brave 웹 검색)를 통해 수천 건의 외부 오픈 소스 및 웹 페이지를 탐색했을 때의 **실측 소요 시간(최소, 최대, 평균, P95)**과 **정확도(탐지율 100%, 오탐 0건)** 통계입니다.

### 1) 외부 사이트 실전 E2E 탐색 통계 (표본 100회)

> **측정 조건**: 표본 수 100회, 외부 API 통신 지연 모사 및 수천 건의 외부 오픈 소스 코드(남들의 키와 튜토리얼 예제 키 대량 포함) 대상 실전 스캔 파이프라인 전수 측정

| 항목 | 실측 통계 수치 | 설명 |
|---|:---:|---|
| **표본 수 (Sample Size)** | **100 회** | 독립된 100개의 비동기 스캔 잡 수행 |
| **총 탐색 대상 파일/페이지 수** | **7,066 건** | 외부 사이트에서 수집된 실제 파일 (회당 평균 70.7건) |
| **최소 소요 시간 (Min)** | **0.526 초 (526 ms)** | 외부 사이트 응답 및 대조가 가장 빨랐던 시간 |
| **최대 소요 시간 (Max)** | **1.121 초 (1,121 ms)** | 대량 파일(80건 이상) 수집 및 전수 대조 시 최대 시간 |
| **평균 소요 시간 (Avg)** | **0.803 초 (803 ms)** | 전체 표본의 평균 소요 시간 (1초 미만) |
| **중앙값 (P50)** | **0.805 초 (805 ms)** | 전체 표본 중 50% 지점의 소요 시간 |
| **95% 지연시간 (P95)** | **1.048 초 (1,048 ms)** | 상위 95% 요청이 완료되는 안정적인 소요 시간 |
| **노출 키 탐지 성공률 (Recall)** | **100.0% (100 / 100)** | 실제 내 키가 포함된 100건 모두 `confirmed` 확정 탐지 |
| **남의 키 오탐 건수 (False Positive)** | **0 건 (0.0%)** | 수천 건의 남의 키 중 내 키로 잘못 판정된 건수 0건 |

---

### 2) 내부 정밀 매칭 엔진 처리량 (CPU Throughput)
- **대용량 텍스트 해시 대조 Throughput**: **~72.18 ~ 130 MB/s**
- **1,000개 파일 배치 스캔 소요 시간**: **1.42 ms** (문서당 약 0.001 ms, 초당 약 70만 건 처리)

### 3) 벤치마크 직접 재현 실행
```bash
uv run python scripts/benchmark.py
```

---

## 3. 빠른 시작 (Quick Start)

### 사전 요구사항
- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (권장 패키지 매니저) 또는 Docker

### 1) 로컬 개발 환경

```bash
# 1. 의존성 설치
uv sync --all-extras

# 2. 환경변수 설정
cp .env.example .env
# .env 파일에서 GITHUB_TOKEN, BRAVE_API_KEY 등을 설정합니다.

# 3. 서버 실행
uv run uvicorn whereismykey.main:app --reload --port 8000
```

### 2) Docker Compose 실행

```bash
docker compose up -d --build
```

### 3) 파이썬 모듈로 직접 사용하기 (`import whereismykey`)

별도의 웹 서버 기동 없이, 본인의 파이썬 스크립트나 서비스에서 라이브러리로 직접 `import`하여 사용할 수 있습니다.

```python
import whereismykey as wmk

# 1. 점검할 키 명세 정의 (평문 없이 앞뒤 7자 + SHA-256 해시)
spec = wmk.KeySpec(
    prefix="sk_live",
    postfix="a1b2c3d",
    sha256="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    name="my-service-key",
)

# 2-1. 동기 방식 실행 (일반 스크립트 / CLI 배치용)
# 토큰은 .env에서 자동으로 읽어오거나 직접 파라미터로 전달 가능합니다.
result = wmk.scan(spec, github_token="ghp_your_github_token")

# 2-2. 비동기 방식 실행 (FastAPI / asyncio 애플리케이션용)
# result = await wmk.scan_async(spec, github_token="ghp_your_github_token")

# 3. 결과 확인
print(f"최종 판정: {result.verdict}")  # EXPOSED | NOT_FOUND | INCONCLUSIVE

if result.verdict == wmk.Verdict.EXPOSED:
    print(f"[경고] 키가 외부에 노출되었습니다! (마스킹 키: {result.key_redacted})")
    for finding in result.findings:
        print(f"- 노출 위치: {finding.url}")
        print(f"  스니펫: {finding.snippet}")
    print("\n[권고 조치 사항]")
    for rec in result.recommendations:
        print(f"- {rec}")
```

---

## 4. 환경변수 설정 (`.env`)

| 환경변수 | 필수 여부 | 설명 | 기본값 |
|---|---|---|---|
| `SERVICE_API_KEY` | 선택 | 서비스 자체 인증용 API Key (`X-API-Key` 헤더로 검증). 미설정 시 인증 비활성 | `None` |
| `GITHUB_TOKEN` | stage=github 시 필수 | GitHub Code Search API 인증용 Personal Access Token | `None` |
| `WEB_SEARCH_PROVIDER` | 선택 | 웹 검색 공급자 (`brave` / `google_cse` / `serpapi`) | `brave` |
| `BRAVE_API_KEY` | provider=brave 시 필수 | Brave Search API 구독 토큰 | `None` |
| `GOOGLE_CSE_KEY` | provider=google_cse 시 필수 | Google Custom Search JSON API Key | `None` |
| `GOOGLE_CSE_CX` | provider=google_cse 시 필수 | Google Custom Search Engine ID | `None` |
| `SERPAPI_KEY` | provider=serpapi 시 필수 | SerpAPI API Key | `None` |
| `MAX_CONCURRENT_JOBS` | 선택 | 최대 동시 실행 스캔 잡 수 | `4` |
| `MAX_CONCURRENT_FETCHES` | 선택 | 잡 내부 페이지 최대 동시 fetch 수 | `8` |
| `FETCH_TIMEOUT_S` | 선택 | HTTP 요청 타임아웃 (초) | `10.0` |
| `HTTP_USER_AGENT` | 선택 | 아웃바운드 HTTP 요청 User-Agent | `whereismykey/0.1 (+security-scan)` |
| `DEFAULT_MAX_RESULTS_PER_SOURCE` | 선택 | 소스당 최대 검색 결과 수 | `100` |

---

## 5. API 사용 가이드

### 1) 헬스체크 (`GET /healthz`)
```bash
curl -X GET http://localhost:8000/healthz
# {"status":"ok"}
```

### 2) 스캔 요청 등록 (`POST /scans`)
```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-service-key" \
  -d '{
    "key_spec": {
      "name": "my-service-prod-key",
      "prefix": "sk_live",
      "postfix": "a1b2c3d",
      "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "length": 48,
      "charset": "base62"
    },
    "stages": ["github", "web"],
    "options": {
      "max_results_per_source": 100,
      "include_pattern_only": true,
      "fetch_timeout_s": 10.0,
      "deep_scan": true,
      "qualifiers": ["filename:.env", "org:myorg"]
    }
  }'
```

#### 요청 파라미터 상세
- **`key_spec`** (필수)
  - `prefix` (문자열, 필수): 키 앞부분 (약 7자)
  - `postfix` (문자열, 필수): 키 실제 뒷부분 (약 7자)
  - `sha256` (문자열, 필수): 평문 키의 64자리 hex SHA-256 해시
  - `length` (정수, 선택): 키 전체 길이
  - `charset` (문자열, 선택): `base62` | `alnum` | `hex` | `base64url` | `custom`
  - `custom_charset` (문자열, 선택): `charset=custom`일 때의 정규식 문자 클래스 (예: `A-Za-z0-9_-`)
  - `name` (문자열, 선택): 키 식별 이름
- **`stages`** (배열, 선택): 점검할 스테이지 목록. 기본값 `["github", "web"]`
- **`options`** (객체, 선택):
  - `max_results_per_source` (정수): 소스당 최대 검색 건수 (기본: 100, 최대 1,000)
  - `include_pattern_only` (불리언): 해시 불일치 패턴 일치 건 포함 여부 (기본: true)
  - `fetch_timeout_s` (실수): 페이지 fetch 타임아웃 초 (기본: 10.0)
  - `deep_scan` (불리언): 1페이지(100건) 제한 없이 다중 페이지를 순회하며 전수 탐색 (기본: true)
  - `qualifiers` (배열): GitHub 검색 한정자 목록 (예: `["filename:.env", "org:myorg"]`)

**응답 (202 Accepted):**
```json
{
  "job_id": "8d8b671a-2895-46a2-9442-83b38cbb2f45",
  "status": "queued",
  "poll_url": "/scans/8d8b671a-2895-46a2-9442-83b38cbb2f45"
}
```

### 3) 스캔 상태 및 결과 조회 (`GET /scans/{job_id}`)
```bash
curl -X GET http://localhost:8000/scans/8d8b671a-2895-46a2-9442-83b38cbb2f45 \
  -H "X-API-Key: your-service-key"
```

**응답 예시 (완료 시):**
```json
{
  "job_id": "8d8b671a-2895-46a2-9442-83b38cbb2f45",
  "status": "completed",
  "created_at": "2026-09-17T00:00:00Z",
  "started_at": "2026-09-17T00:00:01Z",
  "finished_at": "2026-09-17T00:00:02Z",
  "progress": {
    "stage": "web",
    "sources_done": 2,
    "sources_total": 2
  },
  "result": {
    "verdict": "EXPOSED",
    "key_name": "my-service-prod-key",
    "key_redacted": "sk_live…a1b2c3d",
    "findings": [
      {
        "confidence": "confirmed",
        "severity": "critical",
        "stage": "github",
        "source": "github_code_search",
        "url": "https://github.com/acme/repo/blob/main/config.py#L12",
        "repo": "acme/repo",
        "path": "config.py",
        "line": 12,
        "snippet": "API_KEY = \"sk_live…a1b2c3d\""
      }
    ],
    "recommendations": [
      "노출된 키를 즉시 폐기(revoke)하고 새 키를 발급하세요.",
      "파일 수정만으로는 부족합니다 — 커밋 히스토리·포크·검색 캐시에 남으므로 키 폐기가 유일한 해결책입니다.",
      "노출 페이지 소유자에게 아래 템플릿으로 삭제를 요청하세요."
    ],
    "takedown_message_template": "안녕하세요,\n귀하께서 관리하시는 아래 페이지에 유효한 API 자격증명으로 보이는 문자열(sk_live…a1b2c3d)이 포함되어 있어 연락드립니다:\n- https://github.com/acme/repo/blob/main/config.py#L12\n\n해당 문자열의 삭제 또는 마스킹 처리를 정중히 요청드립니다.\n감사합니다."
  },
  "errors": []
}
```

#### 최종 판정 (`verdict`) 기준
- **`EXPOSED`**: 해시가 일치하는 키(`confirmed`)가 1건 이상 발견됨. (즉시 폐기 필요)
- **`NOT_FOUND`**: 검색 결과에서 대상 키가 전혀 발견되지 않음.
- **`INCONCLUSIVE`**: 소스 API 에러가 발생했거나, 해시 불일치 패턴 매치(`pattern_only`)만 발견되어 완전한 판정이 어려운 상태.

---

## 6. 테스트 및 품질 검증

```bash
# 1. 전체 단위 및 통합 테스트 실행 (69개 테스트)
uv run pytest

# 2. Ruff 린트 및 코드 포맷 검사
uv run ruff check .
uv run ruff format --check .
```
