"""
Client for the OSV.dev API (https://osv.dev).

Two-step "batch then hydrate" pattern:
  1. POST /v1/querybatch  -> cheap, returns only vuln IDs + modified timestamps
  2. GET  /v1/vulns/{id}  -> full record (severity, description, fixed versions),
                             fetched once per UNIQUE id and cached, since the
                             same CVE/GHSA commonly affects many packages.

No API key is required. OSV.dev documents no hard rate limit, but we still
batch requests, retry transient failures with backoff, and use a session
with a sane timeout to be a good API citizen.
"""

from __future__ import annotations

import time
from typing import Any, TypedDict

import requests

BASE_URL = "https://api.osv.dev/v1"
BATCH_ENDPOINT = f"{BASE_URL}/querybatch"
VULN_ENDPOINT = f"{BASE_URL}/vulns"

MAX_BATCH_SIZE = 1000  # OSV supports large batches; chunk defensively anyway.
REQUEST_TIMEOUT = 15  # seconds
MAX_RETRIES = 4
BACKOFF_BASE = 1.5  # seconds, doubles-ish each retry


class Dependency(TypedDict):
    name: str
    version: str
    ecosystem: str


def _chunked(items: list[Dependency], size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _request_with_retries(
    session: requests.Session, method: str, url: str, **kwargs: Any
) -> requests.Response:
    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            resp = session.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
            if resp.status_code == 429 or resp.status_code >= 500:
                raise requests.HTTPError(f"Retryable status {resp.status_code}", response=resp)
            resp.raise_for_status()
            return resp
        except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as exc:
            last_exc = exc
            sleep_for = BACKOFF_BASE * (2**attempt)
            time.sleep(sleep_for)
    raise RuntimeError(f"OSV API request failed after {MAX_RETRIES} attempts: {last_exc}")


def batch_query(
    dependencies: list[Dependency], session: requests.Session | None = None
) -> dict[str, set[str]]:
    """
    Query OSV in batches. Returns a dict mapping a dependency key
    "ecosystem/name@version" -> set of vulnerability IDs affecting it.
    """
    session = session or requests.Session()
    results: dict[str, set[str]] = {}

    for chunk in _chunked(dependencies, MAX_BATCH_SIZE):
        payload = {
            "queries": [
                {
                    "package": {"name": dep["name"], "ecosystem": dep["ecosystem"]},
                    "version": dep["version"],
                }
                for dep in chunk
            ]
        }
        resp = _request_with_retries(session, "POST", BATCH_ENDPOINT, json=payload)
        data = resp.json()

        for dep, result in zip(chunk, data.get("results", [])):
            key = f"{dep['ecosystem']}/{dep['name']}@{dep['version']}"
            ids = {v["id"] for v in result.get("vulns", [])}
            if ids:
                results[key] = ids

    return results


def hydrate_vulns(
    vuln_ids: set[str], session: requests.Session | None = None
) -> dict[str, dict[str, Any]]:
    """
    Fetch full vulnerability records for a set of unique OSV/GHSA/PYSEC/etc IDs.
    Each ID is fetched exactly once regardless of how many packages it affects.
    """
    session = session or requests.Session()
    hydrated: dict[str, dict[str, Any]] = {}

    for vuln_id in vuln_ids:
        resp = _request_with_retries(session, "GET", f"{VULN_ENDPOINT}/{vuln_id}")
        hydrated[vuln_id] = resp.json()

    return hydrated
