"""
Tests for multi-file `--file` support in cli.py: scanning 2+ lockfiles in
one invocation, producing one combined JSON/SARIF/PR-comment output. The
osv_client boundary is mocked, same pattern as test_cli.py; see
test_backward_compat.py for the single-file byte-identity regression test
this feature is required not to break.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from dep_gate import cli

NPM_HIGH_RECORD = {
    "id": "GHSA-npm-0001",
    "summary": "An npm issue",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"events": [{"fixed": "4.17.19"}]}],
        }
    ],
}

PYPI_HIGH_RECORD = {
    "id": "GHSA-pypi-0001",
    "summary": "A PyPI issue",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "database_specific": {"severity": "HIGH"},
        }
    ],
}


def _write_npm_lockfile(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}},
            }
        ),
        encoding="utf-8",
    )


def _write_requirements(path: Path) -> None:
    path.write_text("requests==2.6.0\n", encoding="utf-8")


@pytest.fixture
def two_lockfiles(tmp_path: Path) -> tuple[Path, Path]:
    npm_file = tmp_path / "package-lock.json"
    py_file = tmp_path / "requirements.txt"
    _write_npm_lockfile(npm_file)
    _write_requirements(py_file)
    return npm_file, py_file


def _mocked_osv():
    matches = {
        "npm/lodash@4.17.15": {"GHSA-npm-0001"},
        "PyPI/requests@2.6.0": {"GHSA-pypi-0001"},
    }
    hydrated = {"GHSA-npm-0001": NPM_HIGH_RECORD, "GHSA-pypi-0001": PYPI_HIGH_RECORD}
    return patch.object(cli.osv_client, "batch_query", return_value=matches), patch.object(
        cli.osv_client, "hydrate_vulns", return_value=hydrated
    )


def test_build_arg_parser_file_is_repeatable() -> None:
    args = cli.build_arg_parser().parse_args(["--file", "a.json", "--file", "b.txt"])

    assert args.files == ["a.json", "b.txt"]


def test_build_arg_parser_single_file_still_yields_one_element_list() -> None:
    args = cli.build_arg_parser().parse_args(["--file", "a.json"])

    assert args.files == ["a.json"]


def test_run_multi_file_combined_json_has_both_files_with_source_file_tags(
    two_lockfiles: tuple[Path, Path], tmp_path: Path
) -> None:
    npm_file, py_file = two_lockfiles
    json_path = tmp_path / "report.json"
    batch_patch, hydrate_patch = _mocked_osv()

    with batch_patch, hydrate_patch:
        exit_code = cli.run(
            [
                "--file",
                str(npm_file),
                "--file",
                str(py_file),
                "--fail-on",
                "high",
                "--json",
                str(json_path),
            ]
        )

    assert exit_code == 1
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(report) == 2
    by_vuln = {f["vuln_id"]: f for f in report}
    assert by_vuln["GHSA-npm-0001"]["source_file"] == str(npm_file)
    assert by_vuln["GHSA-pypi-0001"]["source_file"] == str(py_file)


def test_run_multi_file_combined_sarif_has_correct_per_file_locations(
    two_lockfiles: tuple[Path, Path], tmp_path: Path
) -> None:
    npm_file, py_file = two_lockfiles
    sarif_path = tmp_path / "report.sarif"
    batch_patch, hydrate_patch = _mocked_osv()

    with batch_patch, hydrate_patch:
        cli.run(
            [
                "--file",
                str(npm_file),
                "--file",
                str(py_file),
                "--fail-on",
                "high",
                "--sarif",
                str(sarif_path),
            ]
        )

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    uris_by_rule = {
        r["ruleId"]: r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in sarif["runs"][0]["results"]
    }
    assert uris_by_rule["GHSA-npm-0001"] == str(npm_file)
    assert uris_by_rule["GHSA-pypi-0001"] == str(py_file)


def test_run_multi_file_pr_comment_shows_both_files_without_overwrite(
    two_lockfiles: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    npm_file, py_file = two_lockfiles
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    batch_patch, hydrate_patch = _mocked_osv()

    with batch_patch, hydrate_patch, patch.object(
        cli.github_client, "upsert_comment"
    ) as mock_upsert:
        cli.run(
            [
                "--file",
                str(npm_file),
                "--file",
                str(py_file),
                "--fail-on",
                "high",
                "--pr-comment",
                "--github-repo",
                "owner/repo",
                "--github-pr-number",
                "7",
            ]
        )

    body = mock_upsert.call_args.args[2]
    assert f"### `{npm_file}`" in body
    assert f"### `{py_file}`" in body
    assert "lodash@4.17.15" in body
    assert "requests@2.6.0" in body
    assert "GHSA-npm-0001" in body
    assert "GHSA-pypi-0001" in body


def test_run_multi_file_exit_1_if_only_one_file_has_blocking_finding(
    two_lockfiles: tuple[Path, Path],
) -> None:
    npm_file, py_file = two_lockfiles
    # Only the npm finding is HIGH; the PyPI one is MODERATE and won't block.
    low_pypi_record = {
        "id": "GHSA-pypi-0001",
        "summary": "not severe",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "database_specific": {"severity": "MODERATE"},
            }
        ],
    }
    matches = {
        "npm/lodash@4.17.15": {"GHSA-npm-0001"},
        "PyPI/requests@2.6.0": {"GHSA-pypi-0001"},
    }
    hydrated = {"GHSA-npm-0001": NPM_HIGH_RECORD, "GHSA-pypi-0001": low_pypi_record}

    with patch.object(cli.osv_client, "batch_query", return_value=matches), patch.object(
        cli.osv_client, "hydrate_vulns", return_value=hydrated
    ):
        exit_code = cli.run(["--file", str(npm_file), "--file", str(py_file), "--fail-on", "high"])

    assert exit_code == 1


def test_run_multi_file_exit_0_if_no_file_has_blocking_finding(
    two_lockfiles: tuple[Path, Path],
) -> None:
    npm_file, py_file = two_lockfiles

    with patch.object(cli.osv_client, "batch_query", return_value={}), patch.object(
        cli.osv_client, "hydrate_vulns", return_value={}
    ):
        exit_code = cli.run(["--file", str(npm_file), "--file", str(py_file), "--fail-on", "high"])

    assert exit_code == 0


def test_run_multi_file_fails_fast_on_first_bad_file_no_osv_call_made(
    two_lockfiles: tuple[Path, Path], tmp_path: Path
) -> None:
    npm_file, _py_file = two_lockfiles
    missing_file = tmp_path / "requirements.txt.does-not-exist"

    with patch.object(cli.osv_client, "batch_query") as mock_batch:
        exit_code = cli.run(["--file", str(npm_file), "--file", str(missing_file)])

    assert exit_code == 2
    mock_batch.assert_not_called()  # fail-fast: no partial scan, no network call at all


def test_run_multi_file_second_file_error_message_names_that_file(
    two_lockfiles: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    npm_file, _py_file = two_lockfiles
    unrecognized = tmp_path / "nope.json"  # not "package-lock.json" - unrecognized type
    unrecognized.write_text("{}", encoding="utf-8")

    exit_code = cli.run(["--file", str(npm_file), "--file", str(unrecognized)])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert str(unrecognized) in captured.out
