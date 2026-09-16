from __future__ import annotations

import logging

from whereismykey.core.redaction import (
    RedactingLogFilter,
    build_snippet,
    redact_in_text,
    redact_key,
)


def test_redact_key_masks_middle() -> None:
    assert redact_key("sk_liveXXXXXXXXXXXXa1b2c3d") == "sk_live…a1b2c3d"


def test_redact_key_full_mask_when_too_short() -> None:
    assert redact_key("short") == "…"
    assert redact_key("exactly14chars") == "…"  # 14 == 7 + 7


def test_redact_key_handles_empty() -> None:
    assert redact_key("") == ""
    assert redact_key(None) == ""


def test_redact_key_custom_lengths() -> None:
    assert redact_key("abcdefghij", prefix_len=2, postfix_len=2) == "ab…ij"


def test_redact_in_text_replaces_all_occurrences() -> None:
    secret = "sk_liveAAAAAAAAAAAAa1b2c3d"
    text = f"key={secret} and again {secret}"
    out = redact_in_text(text, [secret])
    assert secret not in out
    assert out.count("sk_live…a1b2c3d") == 2


def test_redact_in_text_ignores_empty_secret() -> None:
    assert redact_in_text("unchanged", ["", None]) == "unchanged"  # type: ignore[list-item]


def test_build_snippet_masks_match_and_trims_context() -> None:
    secret = "sk_liveBBBBBBBBBBBBa1b2c3d"
    text = "x" * 200 + f"  TOKEN={secret};  " + "y" * 200
    span = (text.index(secret), text.index(secret) + len(secret))
    snippet = build_snippet(text, span, secret, context=10)
    assert secret not in snippet
    assert "sk_live…a1b2c3d" in snippet
    assert snippet.startswith("…")
    assert snippet.endswith("…")
    assert "\n" not in snippet


def test_redacting_log_filter_masks_registered_secret() -> None:
    secret = "sk_liveCCCCCCCCCCCCa1b2c3d"
    flt = RedactingLogFilter()
    flt.add_secret(secret)
    record = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="found %s here",
        args=(secret,),
        exc_info=None,
    )
    assert flt.filter(record) is True
    assert secret not in record.getMessage()
    assert "sk_live…a1b2c3d" in record.getMessage()


def test_redacting_log_filter_noop_without_secrets() -> None:
    flt = RedactingLogFilter()
    record = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="plain message",
        args=(),
        exc_info=None,
    )
    assert flt.filter(record) is True
    assert record.getMessage() == "plain message"
