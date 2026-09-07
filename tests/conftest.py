"""테스트 공용 픽스처/헬퍼."""

from __future__ import annotations

import hashlib

import pytest
from app.core.key_spec import Charset, KeySpec

# 테스트 전역에서 쓰는 가짜 키. 실제 자격증명 아님.
FAKE_KEY = "sk_livexABCDEFGHIJKLMNOPQRSTUVWX0123456a1b2c3d"
FAKE_PREFIX = "sk_live"
FAKE_POSTFIX = "a1b2c3d"
FAKE_SHA256 = hashlib.sha256(FAKE_KEY.encode()).hexdigest()


@pytest.fixture
def fake_key() -> str:
    return FAKE_KEY


@pytest.fixture
def key_spec_no_length() -> KeySpec:
    return KeySpec(
        prefix=FAKE_PREFIX,
        postfix=FAKE_POSTFIX,
        sha256=FAKE_SHA256,
        name="fake",
    )


@pytest.fixture
def key_spec_exact_length() -> KeySpec:
    return KeySpec(
        prefix=FAKE_PREFIX,
        postfix=FAKE_POSTFIX,
        sha256=FAKE_SHA256,
        length=len(FAKE_KEY),
        charset=Charset.BASE62,
        name="fake",
    )
