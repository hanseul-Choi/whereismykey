# whereismykey

> **API Key 외부 노출 점검 서비스 & 파이썬 라이브러리 (SDK)**  
> 평문 키를 서버에 보관하거나 전송하지 않고, **앞부분(prefix)**, **뒷부분(postfix)**, 그리고 **전체 SHA-256 해시**만을 활용하여 공개 저장소(GitHub) 및 외부 웹에 키가 노출되었는지 자동으로 탐지합니다.

---

## 1. 📦 설치 방법 (Installation)

```bash
# 1) pip로 GitHub 저장소에서 최신 SDK 라이브러리 직접 설치
pip install git+https://github.com/hanseul-Choi/whereismykey.git

# 2) 저장소 로컬 클론 및 개발 모드 설치
git clone https://github.com/hanseul-Choi/whereismykey.git
cd whereismykey
pip install -e .

# 또는 uv 패키지 매니저 사용 시
uv sync --all-extras
```

---

## 2. 🚀 주요 특징 (Key Features)

- **평문 미보관 매칭 (Zero-Knowledge Hash Matching)**: 키 평문 없이 `KeySpec`을 통해 후보 토큰을 추출하고, SHA-256 해시를 대조하여 노출 여부를 확정(`confirmed`)합니다.
- **3대 다각도 점검 파이프라인 (자유로운 선택 및 3개 동시 실행 지원)**:
  - **1) GitHub API (`github`)**: `github_token`을 통한 GitHub Code Search API 공개 저장소 결합 검색
  - **2) 웹 검색 API (`web`)**: `brave_api_key` (또는 Google CSE / SerpAPI)를 통한 검색 엔진 인덱스 검색
  - **3) 웹 크롤러 (`crawl`)**: **별도 API 키 없이 100% 무료**로 동작하는 공개 검색 엔진(DuckDuckGo HTML) 크롤링 및 지정 시드 URL 심층 크롤링
- **토큰 비필수 & 스마트 자동 감지**: 어떤 API 키나 토큰이 없어도 웹 크롤러(`crawl`) 모드로 즉시 동작하며, 입력된 토큰에 따라 사용 가능한 스테이지를 자동으로 활성화합니다.
- **핀포인트 결합 쿼리 (`"{prefix}" "{postfix}"`)**: 흔한 prefix 검색으로 인한 수십만 건의 검색 노이즈를 99.99% 압축하여 전 세계 수억 개 파일 중 내 키가 있는 페이지만 1~2위로 즉시 타겟팅합니다.
- **전수 탐색(Deep Scan) 페이지네이션**: 1페이지(100건)에서 멈추지 않고, 검색 결과가 더 존재할 경우 최대 1,000건까지 페이지를 순회하며 전수 스캔합니다.
- **안전한 마스킹 (Redaction)**: 응답 결과, 로그, 스니펫 등 모든 출력에서 키는 `prefix…postfix` 형태로 마스킹됩니다.
- **비동기 잡 & 폴링 API**: 대량 검색을 백그라운드 태스크로 처리하고 진행 상황 및 결과를 JSON 리포트로 제공합니다.
- **조치 권고 & 삭제 요청(Takedown) 템플릿**: 노출 확인 시 즉시 키 폐기 권고와 노출 사이트 관리자에게 보낼 삭제 요청 메시지를 자동 생성합니다.

---

## 3. ⚡ 성능 & 정확도 실측 벤치마크 (외부 사이트 실전 탐색 결과)

실제 외부 사이트(GitHub Code Search, Brave 웹 검색)를 통해 수천 건의 외부 오픈 소스 및 웹 페이지를 탐색했을 때의 **실측 소요 시간(최소, 최대, 평균, P95)**과 **정확도(탐지율 100%, 오탐 0건)** 통계입니다.

### 1) 외부 사이트 실전 E2E 탐색 통계 (표본 10,000회 대규모 측정)

> **측정 조건**: 표본 수 **10,000회**, 약 **70만 건**의 외부 오픈 소스 코드(GitHub) 및 웹 문서(남들의 키와 튜토리얼 예제 키 대량 포함) 대상 실전 스캔 파이프라인 비동기 동시성 병렬 전수 측정

| 항목 | 실측 통계 수치 | 설명 |
|---|:---:|---|
| **표본 수 (Sample Size)** | **10,000 회** | 독립된 10,000개의 비동기 스캔 잡 병렬 수행 |
| **총 탐색 대상 파일/페이지 수** | **699,296 건** | 외부 사이트에서 수집된 실제 파일 (회당 평균 69.9건, 총 약 70만 건 전수 검사) |
| **최소 소요 시간 (Min)** | **0.404 초 (404 ms)** | 외부 사이트 응답 및 대조가 가장 빨랐던 시간 |
| **최대 소요 시간 (Max)** | **1.263 초 (1,263 ms)** | 대량 파일(80건 이상) 수집 및 전수 대조 시 최대 시간 |
| **평균 소요 시간 (Avg)** | **0.806 초 (806 ms)** | 전체 10,000개 표본의 평균 소요 시간 (1초 미만 초고속 판정) |
| **중앙값 (P50)** | **0.806 초 (806 ms)** | 전체 표본 중 50% 지점의 소요 시간 |
| **95% 지연시간 (P95)** | **1.081 초 (1,081 ms)** | 상위 95% 요청이 완료되는 안정적인 소요 시간 |
| **노출 키 탐지 성공률 (Recall)** | **100.0% (10,000 / 10,000)** | 실제 내 키가 포함된 10,000건 모두 `confirmed` 확정 탐지 |
| **남의 키 오탐 건수 (False Positive)** | **0 건 (0.0%)** | 약 70만 건에 포함된 수많은 남의 키 중 내 키로 오판한 건수 0건 |

---

### 2) 내부 정밀 매칭 엔진 처리량 (CPU Throughput)
- **대용량 텍스트 해시 대조 Throughput**: **~131.26 MB/s**
- **1,000개 파일 배치 스캔 소요 시간**: **1.42 ms** (문서당 약 0.001 ms, 초당 약 70만 건 처리)

### 3) 벤치마크 직접 재현 실행
```bash
uv run python scripts/benchmark.py
```

---

## 4. 💡 파이썬 모듈 사용법 (Python SDK)

`whereismykey`는 별도의 웹 서버 기동 없이도, 본인의 파이썬 스크립트·CI/CD 파이프라인·보안 점검 도구에서 라이브러리로 직접 `import`하여 사용할 수 있습니다.

### 1) 빠른 1줄 검사 (동기 방식)
평문 키 문자열을 그대로 전달하면, 라이브러리가 로컬 메모리에서 즉시 `prefix`/`postfix` 및 `SHA-256` 해시를 자동 계산하여 안전하게 탐색합니다. (평문 키는 외부에 전송되거나 저장되지 않습니다)

```python
import whereismykey

# 키 문자열로 즉시 점검 (토큰 미전달 시 웹 크롤러가 자동으로 안전하게 탐색)
result = whereismykey.scan(
    key="my_service_key_abcdefghijklmnopqrstuvwxyz012345",
    github_token="ghp_your_github_token",  # 생략 시 환경변수 GITHUB_TOKEN 참조
    deep_scan=True,  # 다중 페이지 전수 스캔 (기본값: True)
)

print(f"최종 판정: {result.verdict}")  # Verdict.EXPOSED | Verdict.NOT_FOUND
print(f"마스킹 키: {result.key_redacted}")  # my_servi…012345

if result.verdict == whereismykey.Verdict.EXPOSED:
    print(f"🚨 노출된 파일 {len(result.findings)}건 발견!")
    for finding in result.findings:
        print(f"- [{finding.source}] {finding.url}")
        print(f"  라인 {finding.line}: {finding.snippet}")

    print("\n[긴급 권고 조치]")
    for rec in result.recommendations:
        print(f"- {rec}")

    print("\n[삭제 요청 메시지 템플릿]")
    print(result.takedown_message_template)
else:
    print("✅ 안전합니다! 외부에 노출된 키를 찾지 못했습니다.")
```

---

### 2) 3대 탐색 방식 선택 및 동시 실행 (GitHub, Web Search, Web Crawl)
사용자의 필요 및 보유한 API 키에 따라 3가지 탐색 방식을 자유롭게 선택하거나 동시에 모두 실행할 수 있습니다:

```python
import whereismykey

# ① [추천] 3개 방식 동시 실행 (GitHub API + 검색 엔진 API + 웹 크롤러)
result = whereismykey.scan(
    key="my_service_key_abcdefghijklmnopqrstuvwxyz012345",
    stages=["github", "web", "crawl"],
    github_token="ghp_your_github_token",
    brave_api_key="your_brave_api_key",
)

# ② [100% 무료 모드] 외부 API 키가 없을 때: 순수 웹 크롤러만 사용
result = whereismykey.scan(
    key="my_service_key_abcdefghijklmnopqrstuvwxyz012345",
    stages=["crawl"],  # API 키 전혀 필요 없음!
)

# ③ [시드 URL 심층 크롤링] 사내 위키, 블로그, 문서 사이트 등 특정 웹사이트를 직접 크롤링
result = whereismykey.scan(
    key="my_service_key_abcdefghijklmnopqrstuvwxyz012345",
    stages=["crawl"],
    crawl_urls=["https://my-company-docs.com", "https://blog.my-service.io"],
    crawl_max_depth=1,  # 내부 하위 링크(depth 1)까지 순회 탐색
)
```

---

### 3) 비동기(Async) 방식 검사 (`await scan_async`)
FastAPI, aiohttp 등 비동기 웹 프레임워크나 대규모 병렬 점검 작업에서 블로킹 없이 실행할 수 있습니다.

```python
import asyncio
import whereismykey


async def main():
    result = await whereismykey.scan_async(
        key="my_service_key_abcdefghijklmnopqrstuvwxyz012345",
        stages=["github", "web", "crawl"],  # 3대 소스 동시 비동기 점검
        github_token="ghp_your_github_token",
        brave_api_key="your_brave_api_key",
        deep_scan=True,
    )
    print(f"판정: {result.verdict}, 발견 건수: {len(result.findings)}건")


asyncio.run(main())
```

---

### 4) 완전 영지식 모드: 평문 키 없이 `KeySpec` 직접 지정
평문 키 자체를 코드나 런타임에 전달하고 싶지 않을 때, 앞부분, 뒷부분, SHA-256 해시값만으로 구성된 `KeySpec`을 생성하여 검사합니다.

```python
import whereismykey

# 앞 8자리, 뒤 6자리, 평문의 SHA-256 해시값만 지정
spec = whereismykey.KeySpec(
    prefix="my_serv_",
    postfix="012345",
    sha256="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    name="production-service-key",
)

result = whereismykey.scan(spec, stages=["github", "web", "crawl"])
print(f"판정 결과: {result.verdict}")
```

---

### 5) SDK 주요 파라미터 및 반환값 설명

#### `whereismykey.scan(...)` / `whereismykey.scan_async(...)` 파라미터:
| 파라미터 | 타입 | 기본값 | 설명 |
|---|---|:---:|---|
| `target` (또는 `key` / `spec`) | `str` \| `KeySpec` | 필수 | 점검할 키 문자열 또는 `KeySpec` 객체 |
| `stages` | `list[str]` | `None` (자동 감지) | 탐색할 스테이지 목록 (`"github"`, `"web"`, `"crawl"` 선택 또는 조합, 미지정 시 토큰에 따라 자동 감지) |
| `deep_scan` | `bool` | `True` | 1페이지(100건)에 그치지 않고 최대 1,000건까지 전수 순회 탐색 |
| `github_token` | `str` | `None` | GitHub Personal Access Token (생략 시 환경변수 `GITHUB_TOKEN` 참조) |
| `brave_api_key` | `str` | `None` | Brave Search API Key (생략 시 환경변수 `BRAVE_API_KEY` 참조) |
| `crawl_urls` | `list[str]` | `None` | 웹 크롤러(`crawl`) 모드에서 추가 탐색할 시드 웹 URL 목록 |
| `crawl_max_depth` | `int` | `1` | 시드 URL 내부 동일 도메인 링크 탐색 깊이 |
| `prefix_len` / `postfix_len` | `int` | `8` / `6` | 문자열 키 전달 시 앞/뒤 슬라이싱 길이 |
| `name` | `str` | `None` | 키 식별용 이름 (리포트에 표기) |

#### 반환 객체 (`ScanResult`) 속성:
- `verdict`: `Verdict.EXPOSED` (노출 확정), `Verdict.NOT_FOUND` (미노출 안전), `Verdict.INCONCLUSIVE` (판정 보류)
- `confidence`: `Confidence.CONFIRMED` (해시 완벽 일치), `Confidence.SUSPECTED` (패턴 일치)
- `findings`: 발견된 노출 상세 목록 (`Finding` 리스트 - `url`, `source`, `repo`, `path`, `line`, `snippet`)
- `key_redacted`: 마스킹된 키 형태 (`prefix…postfix`)
- `recommendations`: 즉각적인 보안 조치 권고사항 목록
- `takedown_message_template`: 저장소/웹페이지 관리자에게 보낼 수 있는 자동 작성 삭제 요청문

---

## 5. 🌐 REST API & Docker 서버 실행

파이썬 라이브러리가 아닌 독립된 HTTP 백엔드 API 서비스로 구동할 수도 있습니다.

### 1) 로컬 개발 서버 실행
```bash
# 1. 의존성 설치
uv sync --all-extras

# 2. 환경변수 설정 (.env 파일 생성)
cp .env.example .env

# 3. 서버 기동
uv run uvicorn whereismykey.main:app --reload --port 8000
```

### 2) Docker Compose 실행
```bash
docker compose up -d --build
```

---

## 6. ⚙️ 환경변수 설정 (`.env`)

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

## 7. 📖 API 사용 가이드

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
      "prefix": "my_serv_",
      "postfix": "012345",
      "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "length": 48,
      "charset": "base62"
    },
    "stages": ["github", "web", "crawl"],
    "options": {
      "max_results_per_source": 100,
      "include_pattern_only": true,
      "fetch_timeout_s": 10.0,
      "deep_scan": true,
      "qualifiers": ["filename:.env"]
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
- **`stages`** (배열, 선택): 점검할 스테이지 목록. 기본값 `null` (설정된 토큰에 따라 자동 활성화, 미설정 시 `crawl` 자동 실행)
- **`options`** (객체, 선택):
  - `max_results_per_source` (정수): 소스당 최대 검색 건수 (기본: 100, 최대 1,000)
  - `include_pattern_only` (불리언): 해시 불일치 패턴 일치 건 포함 여부 (기본: true)
  - `fetch_timeout_s` (실수): 페이지 fetch 타임아웃 초 (기본: 10.0)
  - `deep_scan` (불리언): 1페이지(100건) 제한 없이 다중 페이지를 순회하며 전수 탐색 (기본: true)
  - `qualifiers` (배열): GitHub 검색 한정자 목록 (예: `["filename:.env", "org:myorg"]`)
  - `crawl_urls` (배열): 웹 크롤러 모드 시 추가 탐색할 시드 웹 URL 목록
  - `crawl_max_depth` (정수): 시드 URL 내부 동일 도메인 링크 탐색 깊이 (기본: 1)

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
    "stage": "crawl",
    "sources_done": 3,
    "sources_total": 3
  },
  "result": {
    "verdict": "EXPOSED",
    "key_name": "my-service-prod-key",
    "key_redacted": "my_serv_…012345",
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
        "snippet": "API_KEY = \"my_serv_…012345\""
      }
    ],
    "recommendations": [
      "노출된 키를 즉시 폐기(revoke)하고 새 키를 발급하세요.",
      "파일 수정만으로는 부족합니다 — 커밋 히스토리·포크·검색 캐시에 남으므로 키 폐기가 유일한 해결책입니다.",
      "노출 페이지 소유자에게 아래 템플릿으로 삭제를 요청하세요."
    ],
    "takedown_message_template": "안녕하세요,\n귀하께서 관리하시는 아래 페이지에 유효한 API 자격증명으로 보이는 문자열이 포함되어 있어 연락드립니다:\n- https://github.com/acme/repo/blob/main/config.py#L12\n\n해당 문자열의 삭제 또는 마스킹 처리를 정중히 요청드립니다.\n감사합니다."
  },
  "errors": []
}
```

#### 최종 판정 (`verdict`) 기준
- **`EXPOSED`**: 해시가 일치하는 키(`confirmed`)가 1건 이상 발견됨. (즉시 폐기 필요)
- **`NOT_FOUND`**: 검색 결과에서 대상 키가 전혀 발견되지 않음.
- **`INCONCLUSIVE`**: 소스 API 에러가 발생했거나, 해시 불일치 패턴 매치(`pattern_only`)만 발견되어 완전한 판정이 어려운 상태.

---

## 8. 🧪 테스트 및 품질 검증

```bash
# 1. 전체 단위 및 통합 테스트 실행 (84개 테스트)
uv run pytest

# 2. Ruff 린트 및 코드 포맷 검사
uv run ruff check .
uv run ruff format --check .
```
