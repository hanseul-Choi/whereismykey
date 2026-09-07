"""환경변수 기반 설정 (단일 진입점)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """`.env` / 환경변수에서 로드되는 애플리케이션 설정."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # API 자체 인증 (비우면 인증 비활성)
    service_api_key: str | None = None

    # 1단계: GitHub
    github_token: str | None = None

    # 2단계: 웹 검색
    web_search_provider: str = "brave"
    brave_api_key: str | None = None
    google_cse_key: str | None = None
    google_cse_cx: str | None = None
    serpapi_key: str | None = None

    # 실행 튜닝
    max_concurrent_jobs: int = 4
    max_concurrent_fetches: int = 8
    fetch_timeout_s: float = 10.0
    http_user_agent: str = "whereismykey/0.1 (+security-scan)"
    default_max_results_per_source: int = 50


@lru_cache
def get_settings() -> Settings:
    """프로세스 수명 동안 재사용되는 설정 싱글턴."""
    return Settings()
