"""
Tests for dep_gate.suppress — pure parsing/matching logic (no network).
Covers PRD.md's requirement that suppressions be auditable, not silent:
every entry must carry an expiry date and a justification, and an expired
entry must stop suppressing (not be silently treated as still active).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dep_gate.suppress import find_active_suppression, load_suppressions

VALID_FILE = """\
# accepted-risk exceptions
- vuln_id: GHSA-jf85-cpcp-j695
  package: lodash
  expires: 2099-12-31
  reason: "Accepted risk - vendor patch pending, tracked in JIRA-1234"

- vuln_id: GHSA-global-0001
  expires: 2099-06-01
  reason: "False positive - not reachable in our usage"
"""


def test_load_suppressions_parses_valid_entries(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(VALID_FILE, encoding="utf-8")

    entries = load_suppressions(str(ignore_file))

    assert len(entries) == 2
    assert entries[0].vuln_id == "GHSA-jf85-cpcp-j695"
    assert entries[0].package == "lodash"
    assert entries[0].expires == "2099-12-31"
    assert "JIRA-1234" in entries[0].reason
    assert entries[1].package is None  # global suppression, no package scoping


def test_load_suppressions_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_suppressions(str(tmp_path / "nope.yml"))


def test_load_suppressions_requires_vuln_id(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text('- expires: 2099-01-01\n  reason: "no id given"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="vuln_id"):
        load_suppressions(str(ignore_file))


def test_load_suppressions_requires_non_blank_reason(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(
        '- vuln_id: GHSA-x\n  expires: 2099-01-01\n  reason: "   "\n', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="reason"):
        load_suppressions(str(ignore_file))


def test_load_suppressions_requires_expires(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text('- vuln_id: GHSA-x\n  reason: "no expiry"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="expires"):
        load_suppressions(str(ignore_file))


def test_load_suppressions_rejects_malformed_date(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(
        '- vuln_id: GHSA-x\n  expires: "next tuesday"\n  reason: "bad date"\n', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="expires"):
        load_suppressions(str(ignore_file))


def test_load_suppressions_content_before_any_dash_raises(tmp_path: Path) -> None:
    # A key: value line before any top-level "- " entry has started -
    # there's nowhere to put it, so this must raise rather than silently
    # drop it or attach it to a phantom entry.
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text('vuln_id: GHSA-x\n', encoding="utf-8")

    with pytest.raises(ValueError, match="expected a top-level"):
        load_suppressions(str(ignore_file))


def test_load_suppressions_line_without_colon_raises(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(
        "- vuln_id: GHSA-x\n  this line has no colon in it\n  expires: 2099-01-01\n"
        '  reason: "test"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="key: value"):
        load_suppressions(str(ignore_file))


def test_find_active_suppression_matches_package_scoped_entry(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(VALID_FILE, encoding="utf-8")
    entries = load_suppressions(str(ignore_file))

    match = find_active_suppression("GHSA-jf85-cpcp-j695", "lodash", entries, today="2020-01-01")

    assert match is not None
    assert match.package == "lodash"


def test_find_active_suppression_package_scoped_does_not_match_other_package(
    tmp_path: Path,
) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(VALID_FILE, encoding="utf-8")
    entries = load_suppressions(str(ignore_file))

    match = find_active_suppression("GHSA-jf85-cpcp-j695", "other-pkg", entries, today="2020-01-01")

    assert match is None


def test_find_active_suppression_global_entry_matches_any_package(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(VALID_FILE, encoding="utf-8")
    entries = load_suppressions(str(ignore_file))

    match = find_active_suppression("GHSA-global-0001", "anything", entries, today="2020-01-01")

    assert match is not None


def test_find_active_suppression_expired_entry_does_not_match(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(VALID_FILE, encoding="utf-8")
    entries = load_suppressions(str(ignore_file))

    # "today" is far past both entries' 2099 expiry dates.
    match = find_active_suppression("GHSA-jf85-cpcp-j695", "lodash", entries, today="2199-01-01")

    assert match is None


def test_find_active_suppression_no_match_returns_none(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(VALID_FILE, encoding="utf-8")
    entries = load_suppressions(str(ignore_file))

    match = find_active_suppression("GHSA-unrelated", "lodash", entries, today="2020-01-01")

    assert match is None
