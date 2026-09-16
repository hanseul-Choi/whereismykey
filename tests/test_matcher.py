from __future__ import annotations

import hashlib

from whereismykey.core.key_spec import Charset, KeySpec
from whereismykey.core.matcher import build_pattern, has_confirmed, scan_text

from tests.conftest import FAKE_KEY, FAKE_POSTFIX, FAKE_PREFIX, FAKE_SHA256


def test_confirmed_match_on_exact_key(key_spec_no_length: KeySpec) -> None:
    text = f'API_KEY = "{FAKE_KEY}"  # do not commit'
    results = scan_text(text, key_spec_no_length)
    assert len(results) == 1
    assert results[0].hash_matched is True
    assert has_confirmed(results) is True
    assert FAKE_KEY not in results[0].snippet
    assert f"{FAKE_PREFIX}…{FAKE_POSTFIX}" in results[0].snippet


def test_pattern_only_when_hash_differs(key_spec_no_length: KeySpec) -> None:
    # prefix/postfix 는 같지만 중간부가 다른 문자열
    other = f"{FAKE_PREFIX}TOTALLYDIFFERENTMIDDLE999{FAKE_POSTFIX}"
    assert hashlib.sha256(other.encode()).hexdigest() != FAKE_SHA256
    results = scan_text(f"token={other}", key_spec_no_length)
    assert len(results) == 1
    assert results[0].hash_matched is False
    assert has_confirmed(results) is False


def test_no_match_without_affixes(key_spec_no_length: KeySpec) -> None:
    assert scan_text("nothing to see here, just prose.", key_spec_no_length) == []


def test_boundary_prevents_substring_match(key_spec_no_length: KeySpec) -> None:
    # prefix 앞에 키 문자가 붙어 있으면 다른 토큰의 일부로 보고 매치하지 않는다
    glued = f"XXX{FAKE_KEY}"
    assert scan_text(glued, key_spec_no_length) == []


def test_trailing_boundary_enforced(key_spec_no_length: KeySpec) -> None:
    glued = f"{FAKE_KEY}TAIL"
    assert scan_text(glued, key_spec_no_length) == []


def test_exact_length_spec_confirms(key_spec_exact_length: KeySpec) -> None:
    results = scan_text(f"  {FAKE_KEY}  ", key_spec_exact_length)
    assert len(results) == 1
    assert results[0].hash_matched is True


def test_exact_length_spec_rejects_wrong_length(key_spec_exact_length: KeySpec) -> None:
    too_long = f"{FAKE_PREFIX}{'A' * 100}{FAKE_POSTFIX}"
    assert scan_text(too_long, key_spec_exact_length) == []


def test_multiple_occurrences_all_reported(key_spec_no_length: KeySpec) -> None:
    text = f"{FAKE_KEY}\nsome lines\n{FAKE_KEY}\n"
    results = scan_text(text, key_spec_no_length)
    assert len(results) == 2
    assert all(r.hash_matched for r in results)


def test_non_greedy_stops_at_first_postfix(key_spec_no_length: KeySpec) -> None:
    # postfix 뒤에 토큰 경계(공백)가 오면 첫 지점에서 끊겨야 한다
    tricky = f"{FAKE_PREFIX}mid{FAKE_POSTFIX} tail{FAKE_POSTFIX}"
    results = scan_text(tricky, key_spec_no_length)
    assert len(results) == 1
    assert results[0].candidate.value == f"{FAKE_PREFIX}mid{FAKE_POSTFIX}"


def test_build_pattern_is_reusable(key_spec_no_length: KeySpec) -> None:
    pat = build_pattern(key_spec_no_length)
    assert pat.search(FAKE_KEY) is not None
    assert pat.search("unrelated") is None


def test_hex_charset_excludes_non_hex_middle() -> None:
    spec = KeySpec(
        prefix="ghp_",
        postfix="beef",
        sha256="b" * 64,
        charset=Charset.HEX,
    )
    # 중간부에 'xyz'(non-hex)가 있어 prefix..postfix 가 hex 로 이어지지 않는다
    assert scan_text("ghp_123xyz456beef", spec) == []
    # 중간부가 모두 hex 면 매치된다
    assert len(scan_text("ghp_123456beef", spec)) == 1
