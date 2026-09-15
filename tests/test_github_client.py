"""
Tests for dep_gate.github_client — the tool's second (opt-in) network
egress point. `render_pr_comment()` is pure/I-O free and tested directly;
`find_existing_comment_id()`/`upsert_comment()` are tested against a
mocked requests.Session, same pattern as tests/test_osv_client.py - no
real network calls. All calls go through `session.request(method, url,
...)` (via `_request_with_retries`), same as osv_client.py, so mocks and
assertions target `session.request`, not `session.get`/`.post`/`.patch`.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from dep_gate.github_client import (
    COMMENT_MARKER,
    MAX_RETRIES,
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


def _fake_response(status_code: int = 200, json_data=None, headers=None) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.json.return_value = json_data if json_data is not None else {}
    if status_code >= 400:
        error = requests.HTTPError(f"{status_code} error", response=resp)
        resp.raise_for_status.side_effect = error
    else:
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
    session.request.return_value = _fake_response(
        200, [{"id": 111, "body": "unrelated"}, {"id": 222, "body": f"{COMMENT_MARKER}\nhi"}]
    )

    result = find_existing_comment_id("owner/repo", 5, "tok", session=session)

    assert result == 222
    args = session.request.call_args.args
    assert args[0] == "GET"
    assert args[1] == "https://api.github.com/repos/owner/repo/issues/5/comments"


def test_find_existing_comment_id_returns_none_when_absent() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _fake_response(200, [{"id": 111, "body": "unrelated"}])

    result = find_existing_comment_id("owner/repo", 5, "tok", session=session)

    assert result is None


def test_upsert_comment_creates_when_no_existing_comment() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _fake_response(200, []),  # GET (find existing)
        _fake_response(201, {"id": 1}),  # POST (create)
    ]

    upsert_comment("owner/repo", 5, "body text", "tok", session=session)

    methods = [c.args[0] for c in session.request.call_args_list]
    assert methods == ["GET", "POST"]


def test_upsert_comment_updates_existing_comment() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _fake_response(200, [{"id": 42, "body": COMMENT_MARKER}]),  # GET (find existing)
        _fake_response(200, {"id": 42}),  # PATCH (update)
    ]

    upsert_comment("owner/repo", 5, "body text", "tok", session=session)

    methods = [c.args[0] for c in session.request.call_args_list]
    assert methods == ["GET", "PATCH"]


def test_upsert_comment_raises_after_retries_exhausted_on_persistent_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("dep_gate.github_client.time.sleep", lambda _: None)
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _fake_response(200, []),  # GET succeeds
        *[_fake_response(500) for _ in range(MAX_RETRIES)],  # POST always 500
    ]

    with pytest.raises(RuntimeError):
        upsert_comment("owner/repo", 5, "body text", "tok", session=session)


def test_request_with_retries_retries_on_429_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("dep_gate.github_client.time.sleep", lambda _: None)
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _fake_response(200, []),  # GET (find existing)
        _fake_response(429),  # POST first attempt: rate limited
        _fake_response(201, {"id": 1}),  # POST second attempt: succeeds
    ]

    upsert_comment("owner/repo", 5, "body text", "tok", session=session)

    assert session.request.call_count == 3


def test_request_with_retries_respects_retry_after_header(monkeypatch: pytest.MonkeyPatch) -> None:
    sleep_calls = []
    monkeypatch.setattr("dep_gate.github_client.time.sleep", lambda s: sleep_calls.append(s))
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _fake_response(200, []),  # GET (find existing)
        _fake_response(429, headers={"Retry-After": "7"}),  # POST rate limited
        _fake_response(201, {"id": 1}),  # POST succeeds
    ]

    upsert_comment("owner/repo", 5, "body text", "tok", session=session)

    assert 7.0 in sleep_calls


def test_request_with_retries_retries_on_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("dep_gate.github_client.time.sleep", lambda _: None)
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _fake_response(200, []),  # GET (find existing)
        requests.ConnectionError("boom"),  # POST first attempt fails
        _fake_response(201, {"id": 1}),  # POST second attempt succeeds
    ]

    upsert_comment("owner/repo", 5, "body text", "tok", session=session)

    assert session.request.call_count == 3


def test_request_with_retries_never_fires_without_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("dep_gate.github_client.time.sleep", lambda _: None)
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _fake_response(200, [])

    find_existing_comment_id("owner/repo", 5, "tok", session=session)

    assert session.request.call_args.kwargs["timeout"] == 15
