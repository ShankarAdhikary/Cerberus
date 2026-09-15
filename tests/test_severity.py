"""
Tests for dep_gate.severity — pure, I/O-free functions, highest coverage
bar per Rules.md. Covers the precedence order from Schema.md §5.2: a
parseable CVSS vector always wins over database_specific.severity, and
absence of both degrades to UNKNOWN rather than raising.
"""

from __future__ import annotations

import pytest

from dep_gate.severity import Severity, assess, fixed_version

CVSS3_HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # base score 7.5 -> HIGH
CVSS3_CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # base score 9.8 -> CRITICAL


def test_assess_cvss_vector_only() -> None:
    record = {
        "severity": [{"type": "CVSS_V3", "score": CVSS3_CRITICAL_VECTOR}],
        "affected": [],
    }

    result = assess(record)

    assert result.level == "CRITICAL"
    assert result.score == pytest.approx(9.8, abs=0.2)
    assert "CVSS" in result.source


def test_assess_database_specific_only() -> None:
    record = {
        "severity": [],
        "affected": [{"database_specific": {"severity": "HIGH"}}],
    }

    result = assess(record)

    assert result == Severity("HIGH", None, "database_specific.severity")


def test_assess_both_present_cvss_wins() -> None:
    record = {
        "severity": [{"type": "CVSS_V3", "score": CVSS3_HIGH_VECTOR}],
        "affected": [{"database_specific": {"severity": "CRITICAL"}}],
    }

    result = assess(record)

    assert result.level == "HIGH"
    assert result.score is not None
    assert "CVSS" in result.source


def test_assess_neither_present_returns_unknown_never_raises() -> None:
    record: dict = {}

    result = assess(record)

    assert result == Severity("UNKNOWN", None, "no severity data")


def test_assess_database_specific_normalizes_medium_to_moderate() -> None:
    record = {"affected": [{"database_specific": {"severity": "medium"}}]}

    result = assess(record)

    assert result.level == "MODERATE"


def test_assess_malformed_cvss_vector_falls_back_gracefully() -> None:
    record = {
        "severity": [{"type": "CVSS_V3", "score": "not-a-real-vector"}],
        "affected": [{"database_specific": {"severity": "LOW"}}],
    }

    result = assess(record)

    assert result.level == "LOW"
    assert result.source == "database_specific.severity"


def test_assess_unrecognized_database_specific_string_ignored() -> None:
    record = {"affected": [{"database_specific": {"severity": "not-a-level"}}]}

    result = assess(record)

    assert result.level == "UNKNOWN"


def test_assess_takes_worst_case_across_multiple_severity_entries() -> None:
    record = {
        "severity": [
            {"type": "CVSS_V3", "score": CVSS3_HIGH_VECTOR},
            {"type": "CVSS_V3", "score": CVSS3_CRITICAL_VECTOR},
        ],
        "affected": [],
    }

    result = assess(record)

    assert result.level == "CRITICAL"


def test_fixed_version_filters_by_matching_package() -> None:
    record = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}],
            },
            {
                "package": {"ecosystem": "PyPI", "name": "unrelated-pkg"},
                "ranges": [{"events": [{"fixed": "9.9.9"}]}],
            },
        ]
    }

    result = fixed_version(record, "npm", "lodash")

    assert result == "4.17.19"


def test_fixed_version_returns_numerically_lowest_when_multiple_fixes() -> None:
    # Regression test: fixed_version() must compare version segments
    # numerically (natural sort), not as plain strings, or "4.17.19" sorts
    # before "4.17.2" lexicographically and produces a misleading
    # "upgrade to" recommendation.
    record = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [
                    {"events": [{"fixed": "4.17.19"}]},
                    {"events": [{"fixed": "4.17.2"}]},
                ],
            }
        ]
    }

    result = fixed_version(record, "npm", "lodash")

    assert result == "4.17.2"


def test_fixed_version_natural_sort_handles_double_digit_minor() -> None:
    record = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "pkg"},
                "ranges": [
                    {"events": [{"fixed": "2.9.0"}]},
                    {"events": [{"fixed": "2.10.0"}]},
                ],
            }
        ]
    }

    result = fixed_version(record, "npm", "pkg")

    assert result == "2.9.0"


def test_fixed_version_returns_none_when_no_fix_published() -> None:
    record = {"affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": []}]}

    result = fixed_version(record, "npm", "lodash")

    assert result is None


def test_fixed_version_returns_none_for_empty_record() -> None:
    assert fixed_version({}, "npm", "lodash") is None


def test_fixed_version_picks_the_range_containing_the_installed_version() -> None:
    # Regression test based on a real OSV record (GHSA-43w2-9j62-hq99 /
    # smallvec@crates.io): two separate `affected` blocks for the SAME
    # package, one covering the 0.x branch (fixed in 0.6.14) and one
    # covering the 1.x branch (fixed in 1.6.1). Blindly taking the
    # numeric-lowest fix across both blocks recommended "upgrade to
    # 0.6.14" for an app pinned at 1.6.0 - a downgrade, not a fix.
    record = {
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "smallvec"},
                "ranges": [{"events": [{"introduced": "0.6.3"}, {"fixed": "0.6.14"}]}],
            },
            {
                "package": {"ecosystem": "crates.io", "name": "smallvec"},
                "ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "1.6.1"}]}],
            },
        ]
    }

    result = fixed_version(record, "crates.io", "smallvec", installed_version="1.6.0")

    assert result == "1.6.1"


def test_fixed_version_multiple_event_pairs_within_one_range() -> None:
    # Regression test based on RUSTSEC-2021-0003's actual shape: a single
    # `ranges` entry with two introduced/fixed event pairs back to back,
    # rather than two separate `affected` blocks.
    record = {
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "smallvec"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0.6.3"},
                            {"fixed": "0.6.14"},
                            {"introduced": "1.0.0"},
                            {"fixed": "1.6.1"},
                        ]
                    }
                ],
            }
        ]
    }

    result = fixed_version(record, "crates.io", "smallvec", installed_version="1.6.0")

    assert result == "1.6.1"


def test_fixed_version_without_installed_version_keeps_prior_behavior() -> None:
    # No installed_version given - falls back to considering every
    # matching-package fix, same as before this regression fix.
    record = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"events": [{"fixed": "4.17.19"}]}],
            }
        ]
    }

    assert fixed_version(record, "npm", "lodash") == "4.17.19"
