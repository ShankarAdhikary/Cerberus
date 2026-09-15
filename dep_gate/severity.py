"""
Turn an OSV vulnerability record into a normalized (level, score, fixed_version).

OSV's 'severity' field is not a single number - it's an array of
{type, score} where 'score' is a CVSS *vector string* (e.g.
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), not a plain 0-10 float.
Many advisories (especially GHSA-sourced ones) skip the CVSS vector
entirely and instead set a plain-text rating in
affected[].database_specific.severity (e.g. "HIGH").

This module tries, in order:
  1. A CVSS v3/v3.1 vector -> compute the base score with the `cvss` package.
  2. A CVSS v2 vector       -> compute the base score with the `cvss` package.
  3. database_specific.severity string (LOW/MODERATE/MEDIUM/HIGH/CRITICAL).
  4. Unknown -> treated as informational, never fails the build on its own.
"""

from __future__ import annotations

import re
from typing import List, NamedTuple, Optional, Tuple

try:
    from cvss import CVSS2, CVSS3
except ImportError:  # pragma: no cover - degrade gracefully if not installed
    CVSS2 = CVSS3 = None

LEVELS = ["UNKNOWN", "LOW", "MODERATE", "HIGH", "CRITICAL"]


class Severity(NamedTuple):
    level: str  # one of LEVELS
    score: Optional[float]  # numeric CVSS base score if available, else None
    source: str  # how we derived it, for transparency in reports


def _level_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _score_from_vector(vector: str) -> Optional[float]:
    if CVSS3 is None:
        return None
    try:
        if vector.upper().startswith("CVSS:3"):
            return float(CVSS3(vector).base_score)
        if CVSS2 is not None:
            return float(CVSS2(vector).base_score)
    except Exception:
        return None
    return None


def assess(vuln_record: dict) -> Severity:
    """Derive the worst-case severity for a hydrated OSV vulnerability record."""
    best: Severity = Severity("UNKNOWN", None, "no severity data")

    # 1 & 2: top-level severity[] with CVSS vectors.
    for entry in vuln_record.get("severity", []):
        vector = entry.get("score", "")
        score = _score_from_vector(vector)
        if score is not None:
            level = _level_from_score(score)
            if LEVELS.index(level) > LEVELS.index(best.level):
                best = Severity(level, score, f"{entry.get('type', 'CVSS')} vector")

    # 3: database_specific.severity text rating (common on GHSA advisories),
    #    used only if we didn't already get a numeric CVSS score above.
    if best.score is None:
        for affected in vuln_record.get("affected", []):
            raw = affected.get("database_specific", {}).get("severity")
            if isinstance(raw, str):
                normalized = raw.strip().upper()
                if normalized == "MEDIUM":
                    normalized = "MODERATE"
                if normalized in LEVELS and LEVELS.index(normalized) > LEVELS.index(best.level):
                    best = Severity(normalized, None, "database_specific.severity")

    return best


_VERSION_PART_RE = re.compile(r"\d+|\D+")


def _version_sort_key(version: str) -> Tuple[Tuple[int, object], ...]:
    """
    Natural-sort key so numeric version segments compare as integers
    (e.g. "4.17.2" < "4.17.19") instead of a plain string sort, which
    would rank "4.17.19" before "4.17.2" on the third character.
    """
    parts = _VERSION_PART_RE.findall(version)
    return tuple((0, int(part)) if part.isdigit() else (1, part) for part in parts)


def fixed_version(
    vuln_record: dict,
    ecosystem: str,
    package_name: str,
    installed_version: Optional[str] = None,
) -> Optional[str]:
    """
    Find the version that fixes this vulnerability for a given package,
    for use in remediation advice (e.g. "upgrade to lodash@4.17.21").

    A single OSV record can cover multiple disjoint vulnerable ranges for
    the SAME package - e.g. a 0.x branch fixed in 0.6.14 and a 1.x branch
    fixed in 1.6.1 (real example: GHSA-43w2-9j62-hq99 / smallvec, which
    splits this across two `affected` blocks; RUSTSEC-2021-0003, the same
    underlying advisory under its other alias, expresses the identical
    two branches as one `ranges` entry with two introduced/fixed event
    pairs back to back - both shapes occur in the live API). Blindly
    taking the numeric-lowest fix across every range can recommend what
    looks like a downgrade. When `installed_version` is given, only
    ranges whose [introduced, fixed) bounds actually contain it are used;
    otherwise every matching-package fix is considered, as before.

    Returns the *lowest applicable* fixed version found, or None if no
    fix is published yet.
    """
    installed_key = _version_sort_key(installed_version) if installed_version is not None else None

    all_fixes: List[str] = []
    in_range_fixes: List[str] = []

    for affected in vuln_record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != package_name:
            continue
        for rng in affected.get("ranges", []):
            current_introduced: Optional[str] = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    current_introduced = event["introduced"]
                elif "fixed" in event:
                    fixed = event["fixed"]
                    all_fixes.append(fixed)
                    if installed_key is not None and _installed_in_range(
                        installed_key, current_introduced, fixed
                    ):
                        in_range_fixes.append(fixed)

    candidates = in_range_fixes or all_fixes
    return min(candidates, key=_version_sort_key) if candidates else None


def _installed_in_range(
    installed_key: Tuple[Tuple[int, object], ...], introduced: Optional[str], fixed: str
) -> bool:
    """True if `installed_key` falls within [introduced, fixed). "0" is OSV's
    sentinel for "no lower bound", same as introduced being absent."""
    if introduced not in (None, "0"):
        if installed_key < _version_sort_key(introduced):
            return False
    return installed_key < _version_sort_key(fixed)
