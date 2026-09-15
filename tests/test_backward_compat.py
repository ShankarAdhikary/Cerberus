"""
Backward-compatibility regression test for multi-file `--file` support
(Rules.md point 7 of the multi-file task): a single `--file X` invocation
must produce byte-identical JSON/SARIF/SBOM output to before multi-file
support existed.

`tests/fixtures/golden_single_file/expected_*` were captured by running
the PRE-refactor `cli.run()` against `golden_single_file/package-lock.json`
with the exact mocked OSV responses reproduced below, then saved verbatim
(the SARIF's `locations[].uri` was replaced with a placeholder, since that
field is expected to hold whatever path was actually passed - not
something either version of the code controls independently). This test
re-runs the SAME scenario through the CURRENT code and diffs the result
against those golden files, rather than merely asserting "it still looks
right" - an actual diff against pre-refactor output is what proves
nothing regressed, not a fresh set of assertions that could just as
easily describe new (wrong) behavior.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from dep_gate import cli

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "golden_single_file"

# Must match exactly what was used to generate the golden fixtures.
HIGH_VULN_RECORD = {
    "id": "GHSA-high-0001",
    "summary": "A high severity issue",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"events": [{"fixed": "4.17.19"}]}],
        }
    ],
}


def test_single_file_json_sarif_sbom_are_byte_identical_to_pre_multi_file_output(
    tmp_path: Path,
) -> None:
    lockfile = FIXTURES_DIR / "package-lock.json"
    key = "npm/lodash@4.17.15"
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    sbom_path = tmp_path / "sbom.json"

    with patch.object(
        cli.osv_client, "batch_query", return_value={key: {"GHSA-high-0001"}}
    ), patch.object(
        cli.osv_client, "hydrate_vulns", return_value={"GHSA-high-0001": HIGH_VULN_RECORD}
    ):
        exit_code = cli.run(
            [
                "--file",
                str(lockfile),
                "--fail-on",
                "high",
                "--json",
                str(json_path),
                "--sarif",
                str(sarif_path),
                "--sbom",
                str(sbom_path),
            ]
        )

    assert exit_code == 1

    actual_json = json.loads(json_path.read_text(encoding="utf-8"))
    expected_json = json.loads((FIXTURES_DIR / "expected_report.json").read_text(encoding="utf-8"))
    assert actual_json == expected_json  # exact match: no source_file field leaked in

    actual_sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    expected_sarif = json.loads(
        (FIXTURES_DIR / "expected_report.sarif").read_text(encoding="utf-8")
    )
    # The URI is whatever path was passed on this run (a tmp fixture path here
    # vs. wherever the golden file was originally captured from) - substitute
    # the placeholder with the real invocation path before comparing, since
    # that's the one field that was never meant to be literally identical.
    expected_sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = str(lockfile)
    assert actual_sarif == expected_sarif

    actual_sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    expected_sbom = json.loads((FIXTURES_DIR / "expected_sbom.json").read_text(encoding="utf-8"))
    assert actual_sbom == expected_sbom
