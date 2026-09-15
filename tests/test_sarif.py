"""
Tests for dep_gate.sarif — pure, I/O-free document construction (no
network, no filesystem). Covers the SARIF 2.1.0 shape, severity->level
mapping, and rule deduplication across repeated vuln IDs.
"""

from __future__ import annotations

from dep_gate.sarif import SARIF_VERSION, build_sarif


def test_build_sarif_empty_findings() -> None:
    sarif = build_sarif([], "package-lock.json")

    assert sarif["version"] == SARIF_VERSION
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_build_sarif_maps_critical_and_high_to_error() -> None:
    findings = [
        {
            "package": "a",
            "version": "1.0.0",
            "vuln_id": "GHSA-1",
            "severity": "CRITICAL",
            "fixed_version": None,
            "summary": "s1",
        },
        {
            "package": "b",
            "version": "2.0.0",
            "vuln_id": "GHSA-2",
            "severity": "HIGH",
            "fixed_version": "2.0.1",
            "summary": "s2",
        },
    ]

    sarif = build_sarif(findings, "package-lock.json")

    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels["GHSA-1"] == "error"
    assert levels["GHSA-2"] == "error"


def test_build_sarif_maps_moderate_to_warning_and_low_unknown_to_note() -> None:
    findings = [
        {
            "package": "a",
            "version": "1.0.0",
            "vuln_id": "GHSA-mod",
            "severity": "MODERATE",
            "fixed_version": None,
            "summary": "",
        },
        {
            "package": "a",
            "version": "1.0.0",
            "vuln_id": "GHSA-low",
            "severity": "LOW",
            "fixed_version": None,
            "summary": "",
        },
        {
            "package": "a",
            "version": "1.0.0",
            "vuln_id": "GHSA-unk",
            "severity": "UNKNOWN",
            "fixed_version": None,
            "summary": "",
        },
    ]

    sarif = build_sarif(findings, "package-lock.json")

    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels["GHSA-mod"] == "warning"
    assert levels["GHSA-low"] == "note"
    assert levels["GHSA-unk"] == "note"


def test_build_sarif_dedupes_rules_across_multiple_findings_of_same_id() -> None:
    findings = [
        {
            "package": "a",
            "version": "1.0.0",
            "vuln_id": "GHSA-shared",
            "severity": "HIGH",
            "fixed_version": "1.0.1",
            "summary": "shared advisory",
        },
        {
            "package": "b",
            "version": "2.0.0",
            "vuln_id": "GHSA-shared",
            "severity": "HIGH",
            "fixed_version": "2.0.1",
            "summary": "shared advisory",
        },
    ]

    sarif = build_sarif(findings, "package-lock.json")

    rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids == ["GHSA-shared"]
    assert len(sarif["runs"][0]["results"]) == 2


def test_build_sarif_result_location_points_at_scanned_file() -> None:
    findings = [
        {
            "package": "a",
            "version": "1.0.0",
            "vuln_id": "GHSA-1",
            "severity": "HIGH",
            "fixed_version": "1.0.1",
            "summary": "s",
        },
    ]

    sarif = build_sarif(findings, "requirements.txt")

    location = sarif["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"


def test_build_sarif_message_mentions_package_and_fix() -> None:
    findings = [
        {
            "package": "lodash",
            "version": "4.17.15",
            "vuln_id": "GHSA-1",
            "severity": "HIGH",
            "fixed_version": "4.17.19",
            "summary": "issue",
        },
    ]

    sarif = build_sarif(findings, "package-lock.json")

    message = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "lodash" in message
    assert "4.17.15" in message
    assert "4.17.19" in message


def test_build_sarif_suppressed_finding_marked_not_omitted() -> None:
    findings = [
        {
            "package": "a",
            "version": "1.0.0",
            "vuln_id": "GHSA-1",
            "severity": "HIGH",
            "fixed_version": None,
            "summary": "",
            "suppressed": True,
            "suppression_reason": "accepted risk",
        },
    ]

    sarif = build_sarif(findings, "package-lock.json")

    result = sarif["runs"][0]["results"][0]
    assert result["suppressions"][0]["kind"] == "external"
