"""
Builds a minimal SARIF 2.1.0 document from the CLI's findings[], for
upload via github/codeql-action/upload-sarif into GitHub's code-scanning
UI. This is a second output format alongside --json, not a replacement -
same findings, different shape for a different consumer.

Deliberately minimal: results are whole-file (no line/column region),
since findings map to a resolved (package, version) pair from a lockfile
parser, not a specific line in it - lockfile.py's parsers don't track
source positions, and fabricating a region would misrepresent the data.
"""

from __future__ import annotations

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# SARIF's result "level" is a fixed enum (none/note/warning/error), coarser
# than our five severity levels - CRITICAL and HIGH both map to "error"
# since SARIF doesn't distinguish beyond that in the level itself (the
# message text still carries the exact severity word).
_LEVEL_BY_SEVERITY: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MODERATE": "warning",
    "LOW": "note",
    "UNKNOWN": "note",
}


def _rule(vuln_id: str) -> dict:
    return {
        "id": vuln_id,
        "shortDescription": {"text": vuln_id},
        "helpUri": f"https://osv.dev/vulnerability/{vuln_id}",
    }


def _result(finding: dict, scanned_file: str | None) -> dict:
    # A multi-file scan tags each finding with its own source_file (see
    # cli.py); that wins when present. A single-file scan never tags
    # findings at all, so every result falls back to the one `scanned_file`
    # the caller passed - this is what keeps single-file SARIF output
    # byte-identical to before multi-file support existed.
    location_file = finding.get("source_file") or scanned_file
    fix = finding.get("fixed_version")
    fix_text = f"upgrade to {fix}" if fix else "no fix published yet"
    message = (
        f"{finding['severity']}: {finding['package']}@{finding['version']} is "
        f"affected by {finding['vuln_id']} ({fix_text})."
    )
    result = {
        "ruleId": finding["vuln_id"],
        "level": _LEVEL_BY_SEVERITY.get(finding["severity"], "note"),
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": location_file}}}],
    }
    if finding.get("suppressed"):
        result["suppressions"] = [
            {"kind": "external", "justification": finding.get("suppression_reason") or ""}
        ]
    return result


def build_sarif(findings: list[dict], scanned_file: str | None = None) -> dict:
    """
    Build a SARIF document (as a plain dict, ready for json.dump).

    `scanned_file` is the fallback location for findings that don't carry
    their own `source_file` (the single-file case - see `_result()`). For
    a multi-file scan, pass `None` and tag every finding with `source_file`
    instead, so each result points at the lockfile it actually came from.
    """
    rules: dict[str, dict] = {}
    results = []
    for finding in findings:
        vuln_id = finding["vuln_id"]
        if vuln_id not in rules:
            rules[vuln_id] = _rule(vuln_id)
        results.append(_result(finding, scanned_file))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dep-gate",
                        "informationUri": "https://osv.dev",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
