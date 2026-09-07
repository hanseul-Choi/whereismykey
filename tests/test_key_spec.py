from __future__ import annotations

import pytest
from app.core.key_spec import (
    DEFAULT_MIDDLE_MAX,
    DEFAULT_MIDDLE_MIN,
    Charset,
    KeySpec,
    KeySpecError,
)

VALID_SHA = "a" * 64


def _spec(**overrides: object) -> KeySpec:
    kwargs: dict[str, object] = {
        "prefix": "sk_live",
        "postfix": "a1b2c3d",
        "sha256": VALID_SHA,
    }
    kwargs.update(overrides)
    return KeySpec(**kwargs)  # type: ignore[arg-type]


def test_valid_minimal_spec() -> None:
    spec = _spec()
    assert spec.prefix == "sk_live"
    assert spec.middle_bounds() == (DEFAULT_MIDDLE_MIN, DEFAULT_MIDDLE_MAX)


def test_sha256_normalized_to_lowercase() -> None:
    spec = _spec(sha256="A" * 64)
    assert spec.sha256 == "a" * 64


@pytest.mark.parametrize("bad", ["", "xyz", "g" * 64, "a" * 63, "a" * 65])
def test_invalid_sha256_rejected(bad: str) -> None:
    with pytest.raises(KeySpecError, match="sha256"):
        _spec(sha256=bad)


def test_missing_prefix_rejected() -> None:
    with pytest.raises(KeySpecError, match="prefix"):
        _spec(prefix="")


def test_missing_postfix_rejected() -> None:
    with pytest.raises(KeySpecError, match="postfix"):
        _spec(postfix="")


def test_length_shorter_than_affixes_rejected() -> None:
    with pytest.raises(KeySpecError, match="length"):
        _spec(length=5)  # 7 + 7 = 14 minimum


def test_custom_charset_requires_value() -> None:
    with pytest.raises(KeySpecError, match="custom_charset"):
        _spec(charset=Charset.CUSTOM)


def test_exact_length_gives_fixed_middle_bounds() -> None:
    spec = _spec(length=40)  # 40 - 7 - 7 = 26
    assert spec.middle_bounds() == (26, 26)


def test_named_charset_class() -> None:
    assert _spec(charset=Charset.HEX).middle_char_class() == "0-9a-fA-F"
    assert _spec(charset=Charset.BASE64URL).middle_char_class() == "A-Za-z0-9_-"


def test_custom_charset_class_passthrough() -> None:
    spec = _spec(charset=Charset.CUSTOM, custom_charset="A-F0-9")
    assert spec.middle_char_class() == "A-F0-9"


def test_redacted_form() -> None:
    assert _spec().redacted() == "sk_live…a1b2c3d"


def test_keyspec_is_frozen() -> None:
    spec = _spec()
    with pytest.raises(Exception):  # noqa: B017 - dataclass FrozenInstanceError
        spec.prefix = "changed"  # type: ignore[misc]
