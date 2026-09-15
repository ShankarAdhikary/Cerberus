"""
A flat-JSON, TTL-based cache of hydrated OSV vuln records
(GET /v1/vulns/{id} responses), keyed by vuln_id, so a CI job that runs
repeatedly against the same repo doesn't re-fetch a record it already
has fresh.

Why TTL instead of OSV's `modified` timestamp: `batch_query()`'s response
does carry a per-result `modified` field (see Schema.md §5.1), which
could in principle drive exact staleness checks - but wiring that through
would change `batch_query()`'s documented, already-tested return shape
(`Dict[str, set[str]]`) into something structurally different, for a
benefit (byte-exact staleness detection) that a bounded TTL already
delivers with far less risk to the existing, well-tested contract. A
security tool's cache staleness window should be small and explicit
either way, so `CACHE_TTL_SECONDS` is deliberately short.
"""

from __future__ import annotations

import json

CACHE_TTL_SECONDS = 6 * 60 * 60  # 6 hours


def load_cache(cache_path: str) -> dict[str, dict]:
    """
    Load the cache file. Returns `{}` if it doesn't exist (first run) or
    is unreadable/corrupt - a broken cache file must never take down the
    scan; it's just treated as an empty cache and rebuilt.
    """
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def save_cache(cache_path: str, cache: dict[str, dict]) -> None:
    """Write the cache file."""
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache, f)


def get_fresh(cache: dict[str, dict], vuln_id: str, now: float) -> dict | None:
    """Return the cached hydrated record for `vuln_id` if still within TTL, else None."""
    entry = cache.get(vuln_id)
    if entry is None:
        return None
    if now - entry["cached_at"] > CACHE_TTL_SECONDS:
        return None
    return entry["record"]


def put(cache: dict[str, dict], vuln_id: str, record: dict, now: float) -> None:
    """Store a freshly-fetched hydrated record in `cache` (mutated in place)."""
    cache[vuln_id] = {"record": record, "cached_at": now}
