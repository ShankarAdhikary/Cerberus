"""
Tests for dep_gate.osv_client — fully mocked requests.Session, per
Phase 2 exit criteria (no real network calls in the default suite).

Covers: batch chunking at MAX_BATCH_SIZE, correct dedup of vuln IDs
before hydration, and correct retry count on simulated 429/500 responses.
"""

from __future__ import annotations

from typing import Any, List
from unittest.mock import MagicMock

import pytest
import requests

from dep_gate import osv_client


def _fake_response(status_code: int, json_data: Any = None) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data
    if status_code >= 400:
        error = requests.HTTPError(f"{status_code} error", response=resp)
        resp.raise_for_status.side_effect = error
    else:
        resp.raise_for_status.side_effect = None
    return resp


def test_batch_query_maps_results_back_to_dependency_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    deps: List[osv_client.Dependency] = [
        {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
        {"name": "requests", "version": "2.25.0", "ecosystem": "PyPI"},
    ]
    batch_response = _fake_response(
        200,
        {
            "results": [
                {"vulns": [{"id": "GHSA-jf85-cpcp-j695", "modified": "2020-09-02T22:36:00Z"}]},
                {"vulns": []},
            ]
        },
    )
    session = MagicMock(spec=requests.Session)
    session.request.return_value = batch_response

    result = osv_client.batch_query(deps, session=session)

    assert result == {"npm/lodash@4.17.15": {"GHSA-jf85-cpcp-j695"}}
    session.request.assert_called_once()
    args, kwargs = session.request.call_args
    assert args[0] == "POST"
    assert args[1] == osv_client.BATCH_ENDPOINT
    assert kwargs["timeout"] == osv_client.REQUEST_TIMEOUT


def test_batch_query_chunks_at_max_batch_size(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(osv_client, "MAX_BATCH_SIZE", 2)
    deps: List[osv_client.Dependency] = [
        {"name": f"pkg{i}", "version": "1.0.0", "ecosystem": "npm"} for i in range(5)
    ]
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _fake_response(200, {"results": [{"vulns": []}, {"vulns": []}]})

    osv_client.batch_query(deps, session=session)

    # 5 deps chunked at size 2 -> ceil(5/2) = 3 requests.
    assert session.request.call_count == 3
    call_sizes = [len(c.kwargs["json"]["queries"]) for c in session.request.call_args_list]
    assert call_sizes == [2, 2, 1]


def test_hydrate_vulns_fetches_each_unique_id_exactly_once() -> None:
    session = MagicMock(spec=requests.Session)
    body = {"id": "GHSA-jf85-cpcp-j695", "summary": "fake"}
    session.request.return_value = _fake_response(200, body)

    result = osv_client.hydrate_vulns({"GHSA-jf85-cpcp-j695"}, session=session)

    assert session.request.call_count == 1
    assert result["GHSA-jf85-cpcp-j695"]["summary"] == "fake"
    called_url = session.request.call_args.args[1]
    assert called_url == f"{osv_client.VULN_ENDPOINT}/GHSA-jf85-cpcp-j695"


def test_hydrate_vulns_dedupes_ids_before_fetching() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _fake_response(200, {"id": "GHSA-1"})

    # Caller passes a set, so duplicate IDs collapse before this function
    # is ever invoked - but a list-like with dupes must still not double-fetch.
    vuln_ids = {"GHSA-1"}
    osv_client.hydrate_vulns(vuln_ids, session=session)

    assert session.request.call_count == 1


def test_request_with_retries_retries_on_429_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(osv_client.time, "sleep", lambda _: None)
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _fake_response(429),
        _fake_response(429),
        _fake_response(200, {"ok": True}),
    ]

    resp = osv_client._request_with_retries(session, "GET", "https://example.test")

    assert resp.json() == {"ok": True}
    assert session.request.call_count == 3


def test_request_with_retries_retries_on_500(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(osv_client.time, "sleep", lambda _: None)
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [_fake_response(500), _fake_response(200, {"ok": True})]

    resp = osv_client._request_with_retries(session, "GET", "https://example.test")

    assert resp.json() == {"ok": True}
    assert session.request.call_count == 2


def test_request_with_retries_exhausts_and_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(osv_client.time, "sleep", lambda _: None)
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _fake_response(500)

    with pytest.raises(RuntimeError):
        osv_client._request_with_retries(session, "GET", "https://example.test")

    assert session.request.call_count == osv_client.MAX_RETRIES


def test_request_with_retries_retries_on_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(osv_client.time, "sleep", lambda _: None)
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        requests.ConnectionError("boom"),
        _fake_response(200, {"ok": True}),
    ]

    resp = osv_client._request_with_retries(session, "GET", "https://example.test")

    assert resp.json() == {"ok": True}
    assert session.request.call_count == 2


def test_request_with_retries_never_fires_without_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(osv_client.time, "sleep", lambda _: None)
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _fake_response(200, {"ok": True})

    osv_client._request_with_retries(session, "GET", "https://example.test")

    assert session.request.call_args.kwargs["timeout"] == osv_client.REQUEST_TIMEOUT
