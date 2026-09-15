"""
Suppression-file support (`.dep-gate-ignore.yml`) for accepted-risk
exceptions, per PRD.md's V1 auditability requirement: a suppression must
never be silent. Every entry requires an expiry date and a justification
string, and an expired entry stops suppressing automatically rather than
staying silently active forever.

The file format is a small, fixed subset of YAML - a top-level list of
flat mappings with plain scalar string values:

    - vuln_id: GHSA-jf85-cpcp-j695
      package: lodash        # optional - omit to suppress across all packages
      expires: 2026-12-31    # required, YYYY-MM-DD
      reason: "Accepted risk - vendor patch pending, tracked in JIRA-1234"

A hand-rolled parser is used instead of a `PyYAML` dependency: the format
is deliberately this narrow (no nesting, no anchors, no flow style), so a
small dedicated parser is both sufficient and avoids adding a third-party
dependency for a single fixed-shape config file.
"""

from __future__ import annotations

import datetime
from typing import NamedTuple


class Suppression(NamedTuple):
    vuln_id: str
    package: str | None  # None means "suppress this vuln_id for any package"
    expires: str  # YYYY-MM-DD, validated at load time
    reason: str


_REQUIRED_FIELDS = ("vuln_id", "expires", "reason")


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def load_suppressions(filepath: str) -> list[Suppression]:
    """
    Parse a `.dep-gate-ignore.yml` file into a list of `Suppression`
    entries. Raises `ValueError` (not a silent skip) if an entry is
    missing a required field, has a blank reason, or an unparseable
    expiry date - a suppression tool that tolerates malformed entries by
    ignoring them would fail open, which is worse than a loud error.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entries: list[dict] = []
    current: dict | None = None

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- "):
            current = {}
            entries.append(current)
            stripped = stripped[2:].strip()
            if not stripped:
                continue

        if current is None:
            raise ValueError(
                f"Malformed {filepath}: expected a top-level '- ' list entry, got: {line!r}"
            )

        if ":" not in stripped:
            raise ValueError(f"Malformed {filepath}: expected 'key: value', got: {line!r}")

        key, _, value = stripped.partition(":")
        current[key.strip()] = _strip_quotes(value.strip())

    suppressions: list[Suppression] = []
    for entry in entries:
        for field in _REQUIRED_FIELDS:
            if not entry.get(field, "").strip():
                raise ValueError(
                    f"{filepath}: suppression entry {entry} is missing a required "
                    f"non-blank '{field}' field"
                )

        expires = entry["expires"]
        try:
            datetime.date.fromisoformat(expires)
        except ValueError as exc:
            raise ValueError(
                f"{filepath}: suppression entry for '{entry['vuln_id']}' has an "
                f"invalid 'expires' date {expires!r} (expected YYYY-MM-DD)"
            ) from exc

        suppressions.append(
            Suppression(
                vuln_id=entry["vuln_id"],
                package=entry.get("package") or None,
                expires=expires,
                reason=entry["reason"],
            )
        )

    return suppressions


def find_active_suppression(
    vuln_id: str,
    package: str,
    suppressions: list[Suppression],
    today: str | None = None,
) -> Suppression | None:
    """
    Return the first non-expired suppression matching `vuln_id` (and
    scoped to `package`, or unscoped), or None. ISO 8601 dates sort
    lexicographically, so a plain string comparison against `today`
    (defaulting to the real current UTC date) is sufficient - no
    date-object arithmetic needed. An entry is still active through the
    end of its `expires` date (inclusive).

    `today` defaults to UTC, not the local system timezone: a suppression
    expiring at a fixed calendar date must evaluate the same way whether
    the tool runs on a developer's laptop or a CI runner, and those can
    differ by a day right at the expiry boundary if tied to local time.
    """
    today = today or datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    for suppression in suppressions:
        if suppression.vuln_id != vuln_id:
            continue
        if suppression.package is not None and suppression.package != package:
            continue
        if today > suppression.expires:
            continue
        return suppression
    return None
