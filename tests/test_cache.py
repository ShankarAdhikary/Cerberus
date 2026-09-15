"""
Tests for dep_gate.cache — a flat-JSON, TTL-based cache of hydrated OSV
vuln records, keyed by vuln_id. No network access.
"""

from __future__ import annotations

import time
from pathlib import Path

from dep_gate.cache import CACHE_TTL_SECONDS, get_fresh, load_cache, put, save_cache


def test_load_cache_missing_file_returns_empty(tmp_path: Path) -> None:
    cache = load_cache(str(tmp_path / "nope.json"))

    assert cache == {}


def test_load_cache_corrupt_file_returns_empty_not_crash(tmp_path: Path) -> None:
    cache_file = tmp_path / "cache.json"
    cache_file.write_text("{not valid json", encoding="utf-8")

    cache = load_cache(str(cache_file))

    assert cache == {}


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    cache_file = tmp_path / "cache.json"
    original = {"GHSA-1": {"record": {"summary": "x"}, "cached_at": 1234.5}}

    save_cache(str(cache_file), original)
    loaded = load_cache(str(cache_file))

    assert loaded == original


def test_get_fresh_returns_record_within_ttl() -> None:
    now = time.time()
    cache = {"GHSA-1": {"record": {"summary": "x"}, "cached_at": now - 10}}

    result = get_fresh(cache, "GHSA-1", now)

    assert result == {"summary": "x"}


def test_get_fresh_returns_none_past_ttl() -> None:
    now = time.time()
    cache = {"GHSA-1": {"record": {"summary": "x"}, "cached_at": now - CACHE_TTL_SECONDS - 10}}

    result = get_fresh(cache, "GHSA-1", now)

    assert result is None


def test_get_fresh_returns_none_when_not_cached() -> None:
    assert get_fresh({}, "GHSA-missing", time.time()) is None


def test_put_stores_record_with_current_timestamp() -> None:
    cache: dict = {}
    now = time.time()

    put(cache, "GHSA-1", {"summary": "x"}, now)

    assert cache["GHSA-1"] == {"record": {"summary": "x"}, "cached_at": now}
