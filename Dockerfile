# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

WORKDIR /app

# uv 설치
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# 의존성 복사 및 캐시 활용 설치
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# 애플리케이션 코드 복사 및 설치
COPY app/ app/
RUN uv sync --frozen --no-dev

# 런타임 이미지
FROM python:3.12-slim AS runner

WORKDIR /app

# 보안을 위한 non-root 사용자 생성
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 appuser

# 빌더 스테이지에서 가상환경 및 코드 복사
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/app /app/app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
