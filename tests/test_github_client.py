"""
Tests for dep_gate.github_client — the tool's second (opt-in) network
egress point. `render_pr_comment()` is pure/I-O free and tested directly;
`find_existing_comment_id()`/`upsert_comment()` are tested against a
mocked requests.Session, same pattern as tests/test_osv_client.py - no
real network calls.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from dep_gate.github_client import (
    COMMENT_MARKER,
    find_existing_comment_id,
    render_pr_comment,
    upsert_comment,
)

BLOCKING_FINDING = {
    "package": "lodash",
    "version": "4.17.15",
    "vuln_id": "GHSA-yyyy",
    "severity": "HIGH",
    "fixed_version": "4.17.19",
}


def _fake_response(status_code: int = 200, json_data=None) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.raise_for_status.side_effect = None
    return resp


def test_render_pr_comment_failed_scan_shows_only_blocking_findings() -> None:
    body = render_pr_comment(
        blocking=[BLOCKING_FINDING],
        scanned_count=47,
        fail_on="high",
        diff_mode=True,
        base_ref="origin/main",
    )

    assert "❌ Failed" in body
    assert "1 finding(s) at or above `high`" in body
    assert "lodash@4.17.15" in body
    assert "GHSA-yyyy" in body
    assert "Upgrade to `4.17.19`" in body
    assert COMMENT_MARKER in body


def test_render_pr_comment_passed_scan_has_no_findings_table_row() -> None:
    body = render_pr_comment(
        blocking=[], scanned_count=10, fail_on="high", diff_mode=False, base_ref=None
    )

    assert "✅ Passed" in body
    assert "lodash" not in body


def test_render_pr_comment_never_includes_raw_cvss_vector() -> None:
    finding = dict(BLOCKING_FINDING, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    body = render_pr_comment(
        blocking=[finding], scanned_count=1, fail_on="high", diff_mode=False, base_ref=None
    )

    assert "CVSS:3.1" not in body


def test_render_pr_comment_mentions_diff_mode_base_ref() -> None:
    body = render_pr_comment(
        blocking=[], scanned_count=5, fail_on="high", diff_mode=True, base_ref="origin/main"
    )

    assert "diff-only vs `origin/main`" in body


def test_render_pr_comment_no_fix_shown_as_no_fix_yet() -> None:
    finding = dict(BLOCKING_FINDING, fixed_version=None)
    body = render_pr_comment(
        blocking=[finding], scanned_count=1, fail_on="high", diff_mode=False, base_ref=None
    )

    assert "no fix yet" in body


def test_find_existing_comment_id_returns_match() -> None:
    session = MagicMock(spec=requests.Session)
    session.get.return_value = _fake_response(
        200, [{"id": 111, "body": "unrelated"}, {"id": 222, "body": f"{COMMENT_MARKER}\nhi"}]
    )

    result = find_existing_comment_id("owner/repo", 5, "tok", session=session)

    assert result == 222


def test_find_existing_comment_id_returns_none_when_absent() -> None:
    session = MagicMock(spec=requests.Session)
    session.get.return_value = _fake_response(200, [{"id": 111, "body": "unrelated"}])

    result = find_existing_comment_id("owner/repo", 5, "tok", session=session)

    assert result is None


def test_upsert_comment_creates_when_no_existing_comment() -> None:
    session = MagicMock(spec=requests.Session)
    session.get.return_value = _fake_response(200, [])
    session.post.return_value = _fake_response(201, {"id": 1})

    upsert_comment("owner/repo", 5, "body text", "tok", session=session)

    session.post.assert_called_once()
    session.patch.assert_not_called()


def test_upsert_comment_updates_existing_comment() -> None:
    session = MagicMock(spec=requests.Session)
    session.get.return_value = _fake_response(200, [{"id": 42, "body": COMMENT_MARKER}])
    session.patch.return_value = _fake_response(200, {"id": 42})

    upsert_comment("owner/repo", 5, "body text", "tok", session=session)

    session.patch.assert_called_once()
    session.post.assert_not_called()


def test_upsert_comment_raises_on_http_error() -> None:
    session = MagicMock(spec=requests.Session)
    session.get.return_value = _fake_response(200, [])
    bad_response = _fake_response(500)
    bad_response.raise_for_status.side_effect = requests.HTTPError("boom")
    session.post.return_value = bad_response

    with pytest.raises(requests.HTTPError):
        upsert_comment("owner/repo", 5, "body text", "tok", session=session)
