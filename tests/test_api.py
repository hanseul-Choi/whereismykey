"""FastAPI 엔드포인트 테스트."""

from __future__ import annotations

import httpx
import pytest
from app.config import Settings, get_settings
from app.main import app
from httpx import ASGITransport

from tests.conftest import FAKE_POSTFIX, FAKE_PREFIX, FAKE_SHA256


@pytest.mark.asyncio
async def test_healthz_endpoint() -> None:
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_create_and_get_scan_job() -> None:
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        payload = {
            "key_spec": {
                "name": "my-test-key",
                "prefix": FAKE_PREFIX,
                "postfix": FAKE_POSTFIX,
                "sha256": FAKE_SHA256,
            },
            "stages": ["github", "web"],
            "options": {
                "max_results_per_source": 10,
                "include_pattern_only": True,
            },
        }

        # 1. POST /scans -> 202 Accepted
        post_resp = await client.post("/scans", json=payload)
        assert post_resp.status_code == 202
        data = post_resp.json()
        assert "job_id" in data
        assert data["status"] == "queued"
        job_id = data["job_id"]
        assert data["poll_url"] == f"/scans/{job_id}"

        # 2. GET /scans/{job_id} -> 200 OK
        get_resp = await client.get(f"/scans/{job_id}")
        assert get_resp.status_code == 200
        job_data = get_resp.json()
        assert job_data["job_id"] == job_id
        assert job_data["status"] in ["queued", "running", "completed", "failed"]


@pytest.mark.asyncio
async def test_create_scan_invalid_spec() -> None:
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        payload = {
            "key_spec": {
                "prefix": FAKE_PREFIX,
                "postfix": FAKE_POSTFIX,
                "sha256": "invalid-short-hash",
            }
        }
        resp = await client.post("/scans", json=payload)
        assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_scan_not_found() -> None:
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/scans/non-existent-uuid")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_api_authentication(monkeypatch: pytest.MonkeyPatch) -> None:
    test_settings = Settings(service_api_key="secret-service-token")
    app.dependency_overrides[get_settings] = lambda: test_settings

    try:
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # 1. healthz는 인증 없이 접근 가능
            health_resp = await client.get("/healthz")
            assert health_resp.status_code == 200

            # 2. 인증 헤더 없이 /scans 호출 시 401
            no_auth_resp = await client.post("/scans", json={})
            assert no_auth_resp.status_code == 401

            # 3. 잘못된 인증 헤더
            bad_auth_resp = await client.post(
                "/scans",
                json={},
                headers={"X-API-Key": "wrong-token"},
            )
            assert bad_auth_resp.status_code == 401

            # 4. 올바른 인증 헤더
            payload = {
                "key_spec": {
                    "prefix": FAKE_PREFIX,
                    "postfix": FAKE_POSTFIX,
                    "sha256": FAKE_SHA256,
                }
            }
            good_auth_resp = await client.post(
                "/scans",
                json=payload,
                headers={"X-API-Key": "secret-service-token"},
            )
            assert good_auth_resp.status_code == 202
    finally:
        app.dependency_overrides.clear()
