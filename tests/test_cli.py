"""
End-to-end tests for dep_gate.cli.run() — the OSV client boundary
(osv_client.batch_query / hydrate_vulns) is mocked via unittest.mock.patch,
but parsing, diffing, severity assessment, and exit-code logic all run for
real. Asserts the exact exit codes (0/1/2) for every scenario in
AppFlow.md §3.
"""

from __future__ import annotations

import builtins
import importlib
import json
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from dep_gate import cli


@contextmanager
def _patched_osv(batch_result: dict, hydrate_result: dict) -> Iterator[None]:
    """Patch the osv_client boundary only, per TechSpec.md's network-boundary rule."""
    with (
        patch.object(cli.osv_client, "batch_query", return_value=batch_result),
        patch.object(cli.osv_client, "hydrate_vulns", return_value=hydrate_result),
    ):
        yield


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

LOW_VULN_RECORD = {
    "id": "GHSA-low-0001",
    "summary": "A low severity issue",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "database_specific": {"severity": "LOW"},
        }
    ],
}


def _write_npm_lockfile(path: Path, deps: dict[str, str]) -> None:
    packages = {"": {"name": "sample", "version": "1.0.0"}}
    for name, version in deps.items():
        packages[f"node_modules/{name}"] = {"version": version}
    path.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")


@pytest.fixture
def lockfile(tmp_path: Path) -> Path:
    path = tmp_path / "package-lock.json"
    _write_npm_lockfile(path, {"lodash": "4.17.15"})
    return path


def test_run_passing_scan_exits_0_no_vulns(lockfile: Path) -> None:
    with (
        patch.object(cli.osv_client, "batch_query", return_value={}),
        patch.object(cli.osv_client, "hydrate_vulns", return_value={}),
    ):
        exit_code = cli.run(["--file", str(lockfile)])

    assert exit_code == 0


def test_run_failing_scan_at_threshold_exits_1(lockfile: Path) -> None:
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(["--file", str(lockfile), "--fail-on", "high"])

    assert exit_code == 1


def test_run_finding_below_threshold_does_not_fail(lockfile: Path) -> None:
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-low-0001"}}, {"GHSA-low-0001": LOW_VULN_RECORD}):
        exit_code = cli.run(["--file", str(lockfile), "--fail-on", "high"])

    assert exit_code == 0


@pytest.mark.parametrize(
    "fail_on,expected_exit",
    [
        ("low", 1),
        ("moderate", 1),
        ("high", 1),
        ("critical", 0),
    ],
)
def test_run_threshold_boundaries(lockfile: Path, fail_on: str, expected_exit: int) -> None:
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(["--file", str(lockfile), "--fail-on", fail_on])

    assert exit_code == expected_exit


def test_run_unknown_severity_never_blocks(lockfile: Path) -> None:
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-unknown-0001"}}, {"GHSA-unknown-0001": {}}):
        exit_code = cli.run(["--file", str(lockfile), "--fail-on", "low"])

    assert exit_code == 0


def test_run_api_failure_default_fail_closed_exits_1(lockfile: Path) -> None:
    with patch.object(cli.osv_client, "batch_query", side_effect=RuntimeError("OSV down")):
        exit_code = cli.run(["--file", str(lockfile)])

    assert exit_code == 1


def test_run_api_failure_with_fail_open_exits_0(lockfile: Path) -> None:
    with patch.object(cli.osv_client, "batch_query", side_effect=RuntimeError("OSV down")):
        exit_code = cli.run(["--file", str(lockfile), "--fail-open"])

    assert exit_code == 0


def test_run_hydrate_failure_also_respects_fail_open(lockfile: Path) -> None:
    key = "npm/lodash@4.17.15"
    batch_result = {key: {"GHSA-high-0001"}}
    with (
        patch.object(cli.osv_client, "batch_query", return_value=batch_result),
        patch.object(cli.osv_client, "hydrate_vulns", side_effect=RuntimeError("OSV down")),
    ):
        exit_code = cli.run(["--file", str(lockfile), "--fail-open"])

    assert exit_code == 0


def test_run_malformed_file_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text("{not valid json", encoding="utf-8")

    exit_code = cli.run(["--file", str(bad)])

    assert exit_code == 2


def test_run_missing_file_exits_2(tmp_path: Path) -> None:
    missing = tmp_path / "package-lock.json"

    exit_code = cli.run(["--file", str(missing)])

    assert exit_code == 2


def test_run_unrecognized_file_type_exits_2(tmp_path: Path) -> None:
    unknown = tmp_path / "deps.yaml"
    unknown.write_text("name: foo\n", encoding="utf-8")

    exit_code = cli.run(["--file", str(unknown)])

    assert exit_code == 2


def test_run_empty_lockfile_exits_0(tmp_path: Path) -> None:
    empty = tmp_path / "package-lock.json"
    empty.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}}}), encoding="utf-8")

    exit_code = cli.run(["--file", str(empty)])

    assert exit_code == 0


def test_run_scans_go_sum_lockfile(tmp_path: Path) -> None:
    go_sum = tmp_path / "go.sum"
    go_sum.write_text(
        "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n"
        "github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n",
        encoding="utf-8",
    )
    go_vuln_record = {
        "id": "GHSA-go-0001",
        "summary": "A Go module issue",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "github.com/pkg/errors"},
                "database_specific": {"severity": "HIGH"},
            }
        ],
    }
    key = "Go/github.com/pkg/errors@v0.9.1"
    with _patched_osv({key: {"GHSA-go-0001"}}, {"GHSA-go-0001": go_vuln_record}):
        exit_code = cli.run(["--file", str(go_sum), "--fail-on", "high"])

    assert exit_code == 1


def test_run_scans_cargo_lock_lockfile(tmp_path: Path) -> None:
    cargo_lock = tmp_path / "Cargo.lock"
    cargo_lock.write_text(
        "version = 3\n\n"
        "[[package]]\n"
        'name = "serde"\n'
        'version = "1.0.195"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        encoding="utf-8",
    )
    rust_vuln_record = {
        "id": "GHSA-rust-0001",
        "summary": "A crates.io crate issue",
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "serde"},
                "database_specific": {"severity": "HIGH"},
            }
        ],
    }
    key = "crates.io/serde@1.0.195"
    with _patched_osv({key: {"GHSA-rust-0001"}}, {"GHSA-rust-0001": rust_vuln_record}):
        exit_code = cli.run(["--file", str(cargo_lock), "--fail-on", "high"])

    assert exit_code == 1


def test_run_pr_comment_missing_required_args_exits_2(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(["--file", str(lockfile), "--pr-comment"])

    assert exit_code == 2


def test_run_pr_comment_posts_and_does_not_change_exit_code(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    key = "npm/lodash@4.17.15"
    with (
        _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}),
        patch.object(cli.github_client, "upsert_comment") as mock_upsert,
    ):
        exit_code = cli.run(
            [
                "--file",
                str(lockfile),
                "--fail-on",
                "high",
                "--pr-comment",
                "--github-repo",
                "owner/repo",
                "--github-pr-number",
                "7",
            ]
        )

    assert exit_code == 1  # unchanged from the non-pr-comment scenario
    mock_upsert.assert_called_once()
    call_args = mock_upsert.call_args.args
    assert call_args[0] == "owner/repo"
    assert call_args[1] == 7
    assert "lodash" in call_args[2]
    assert call_args[3] == "fake-token"


def test_run_pr_comment_posting_failure_does_not_change_exit_code(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    key = "npm/lodash@4.17.15"
    with (
        _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}),
        patch.object(cli.github_client, "upsert_comment", side_effect=RuntimeError("boom")),
    ):
        exit_code = cli.run(
            [
                "--file",
                str(lockfile),
                "--fail-on",
                "high",
                "--pr-comment",
                "--github-repo",
                "owner/repo",
                "--github-pr-number",
                "7",
            ]
        )

    assert exit_code == 1  # a posting failure never flips the security-relevant result


def test_run_without_pr_comment_never_touches_github_client(lockfile: Path) -> None:
    key = "npm/lodash@4.17.15"
    with (
        _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}),
        patch.object(cli.github_client, "upsert_comment") as mock_upsert,
    ):
        cli.run(["--file", str(lockfile), "--fail-on", "high"])

    mock_upsert.assert_not_called()


def test_run_cache_file_skips_fetching_fresh_cached_id(lockfile: Path, tmp_path: Path) -> None:
    cache_file = tmp_path / "cache.json"
    cache_file.write_text(
        json.dumps({"GHSA-high-0001": {"record": HIGH_VULN_RECORD, "cached_at": time.time()}}),
        encoding="utf-8",
    )
    key = "npm/lodash@4.17.15"
    hydrate_calls = []

    def _fake_hydrate(vuln_ids, session=None):
        hydrate_calls.append(set(vuln_ids))
        return {}

    with (
        patch.object(cli.osv_client, "batch_query", return_value={key: {"GHSA-high-0001"}}),
        patch.object(cli.osv_client, "hydrate_vulns", side_effect=_fake_hydrate),
    ):
        exit_code = cli.run(
            ["--file", str(lockfile), "--fail-on", "high", "--cache-file", str(cache_file)]
        )

    assert hydrate_calls == []  # fresh cache hit - no network call for this id at all
    assert exit_code == 1  # still correctly evaluated from the cached record


def test_run_cache_file_fetches_uncached_id_and_persists_it(lockfile: Path, tmp_path: Path) -> None:
    cache_file = tmp_path / "cache.json"
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(
            ["--file", str(lockfile), "--fail-on", "high", "--cache-file", str(cache_file)]
        )

    assert exit_code == 1
    saved = json.loads(cache_file.read_text(encoding="utf-8"))
    assert saved["GHSA-high-0001"]["record"] == HIGH_VULN_RECORD


def test_run_cache_file_expired_entry_is_refetched(lockfile: Path, tmp_path: Path) -> None:
    cache_file = tmp_path / "cache.json"
    stale_ts = time.time() - cli.cache_module.CACHE_TTL_SECONDS - 100
    cache_file.write_text(
        json.dumps({"GHSA-high-0001": {"record": {"stale": True}, "cached_at": stale_ts}}),
        encoding="utf-8",
    )
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(
            ["--file", str(lockfile), "--fail-on", "high", "--cache-file", str(cache_file)]
        )

    assert exit_code == 1  # used the freshly re-fetched record, not the stale cached one


def test_run_without_cache_file_behaves_as_before(lockfile: Path) -> None:
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(["--file", str(lockfile), "--fail-on", "high"])

    assert exit_code == 1


def test_run_writes_sarif_report(lockfile: Path, tmp_path: Path) -> None:
    key = "npm/lodash@4.17.15"
    sarif_path = tmp_path / "report.sarif"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(["--file", str(lockfile), "--sarif", str(sarif_path)])

    assert exit_code == 1
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "GHSA-high-0001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == str(lockfile)


def test_run_sarif_not_written_on_usage_error(tmp_path: Path) -> None:
    missing = tmp_path / "package-lock.json"
    sarif_path = tmp_path / "report.sarif"

    exit_code = cli.run(["--file", str(missing), "--sarif", str(sarif_path)])

    assert exit_code == 2
    assert not sarif_path.exists()


def test_run_ignore_file_suppresses_matching_finding(lockfile: Path, tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(
        "- vuln_id: GHSA-high-0001\n"
        "  package: lodash\n"
        "  expires: 2099-01-01\n"
        '  reason: "accepted risk"\n',
        encoding="utf-8",
    )
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(
            ["--file", str(lockfile), "--fail-on", "high", "--ignore-file", str(ignore_file)]
        )

    assert exit_code == 0


def test_run_ignore_file_expired_entry_still_blocks(lockfile: Path, tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(
        "- vuln_id: GHSA-high-0001\n" "  expires: 2000-01-01\n" '  reason: "expired long ago"\n',
        encoding="utf-8",
    )
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(
            ["--file", str(lockfile), "--fail-on", "high", "--ignore-file", str(ignore_file)]
        )

    assert exit_code == 1


def test_run_ignore_file_package_scoped_does_not_suppress_other_package(
    lockfile: Path, tmp_path: Path
) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text(
        "- vuln_id: GHSA-high-0001\n"
        "  package: some-other-package\n"
        "  expires: 2099-01-01\n"
        '  reason: "wrong package"\n',
        encoding="utf-8",
    )
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(
            ["--file", str(lockfile), "--fail-on", "high", "--ignore-file", str(ignore_file)]
        )

    assert exit_code == 1


def test_run_ignore_file_malformed_exits_2(lockfile: Path, tmp_path: Path) -> None:
    ignore_file = tmp_path / ".dep-gate-ignore.yml"
    ignore_file.write_text("- vuln_id: GHSA-x\n", encoding="utf-8")  # missing expires/reason

    exit_code = cli.run(["--file", str(lockfile), "--ignore-file", str(ignore_file)])

    assert exit_code == 2


def test_run_json_includes_suppressed_field_only_with_ignore_file(
    lockfile: Path, tmp_path: Path
) -> None:
    key = "npm/lodash@4.17.15"
    report_path = tmp_path / "report.json"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        cli.run(["--file", str(lockfile), "--json", str(report_path)])

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert "suppressed" not in report[0]


def test_run_writes_sbom_regardless_of_findings(lockfile: Path, tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom.json"
    with _patched_osv({}, {}):
        exit_code = cli.run(["--file", str(lockfile), "--sbom", str(sbom_path)])

    assert exit_code == 0
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["components"] == [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.15",
            "purl": "pkg:npm/lodash@4.17.15",
        }
    ]


def test_run_writes_sbom_even_on_failing_scan(lockfile: Path, tmp_path: Path) -> None:
    key = "npm/lodash@4.17.15"
    sbom_path = tmp_path / "sbom.json"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(
            ["--file", str(lockfile), "--sbom", str(sbom_path), "--fail-on", "high"]
        )

    assert exit_code == 1
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert len(sbom["components"]) == 1


def test_run_sbom_not_written_on_usage_error(tmp_path: Path) -> None:
    missing = tmp_path / "package-lock.json"
    sbom_path = tmp_path / "sbom.json"

    exit_code = cli.run(["--file", str(missing), "--sbom", str(sbom_path)])

    assert exit_code == 2
    assert not sbom_path.exists()


def test_run_sbom_respects_diff_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(["init", "-b", "main"], repo)
    _run_git(["config", "user.email", "t@t.com"], repo)
    _run_git(["config", "user.name", "T"], repo)

    lockfile_path = repo / "package-lock.json"
    _write_npm_lockfile(lockfile_path, {"lodash": "4.17.15"})
    _run_git(["add", "package-lock.json"], repo)
    _run_git(["commit", "-m", "base"], repo)

    _write_npm_lockfile(lockfile_path, {"lodash": "4.17.15", "left-pad": "1.3.0"})
    _run_git(["add", "package-lock.json"], repo)
    _run_git(["commit", "-m", "add left-pad"], repo)

    monkeypatch.chdir(repo)
    sbom_path = tmp_path / "sbom.json"
    with _patched_osv({}, {}):
        cli.run(
            [
                "--file",
                "package-lock.json",
                "--diff-only",
                "--base-ref",
                "HEAD~1",
                "--sbom",
                str(sbom_path),
            ]
        )

    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert [c["name"] for c in sbom["components"]] == ["left-pad"]


def test_run_json_omits_source_by_default(lockfile: Path, tmp_path: Path) -> None:
    key = "npm/lodash@4.17.15"
    report_path = tmp_path / "report.json"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        cli.run(["--file", str(lockfile), "--json", str(report_path)])

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert "source" not in report[0]


def test_run_verbose_includes_source_in_json(lockfile: Path, tmp_path: Path) -> None:
    key = "npm/lodash@4.17.15"
    report_path = tmp_path / "report.json"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        cli.run(["--file", str(lockfile), "--json", str(report_path), "--verbose"])

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report[0]["source"] == "CVSS_V3 vector"


def test_run_verbose_does_not_change_exit_code_or_severity(lockfile: Path) -> None:
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(["--file", str(lockfile), "--fail-on", "high", "--verbose"])

    assert exit_code == 1


def test_run_non_verbose_plain_output_omits_source(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setattr(cli, "_RICH", False)
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        cli.run(["--file", str(lockfile)])

    captured = capsys.readouterr()
    assert "source:" not in captured.out


def test_run_verbose_plain_output_includes_source(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setattr(cli, "_RICH", False)
    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        cli.run(["--file", str(lockfile), "--verbose"])

    captured = capsys.readouterr()
    assert "source: CVSS_V3 vector" in captured.out


def test_run_picks_fix_version_from_range_containing_installed_version(
    lockfile: Path, tmp_path: Path
) -> None:
    # End-to-end regression test for the multi-range fixed_version() bug:
    # cli.run() must pass the installed version through so a record
    # covering multiple branches (real shape: GHSA-43w2-9j62-hq99) doesn't
    # recommend a downgrade. lockfile pins lodash@4.17.15.
    multi_range_record = {
        "id": "GHSA-multi-0001",
        "summary": "multi-branch advisory",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"events": [{"introduced": "2.0.0"}, {"fixed": "3.0.0"}]}],
            },
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"events": [{"introduced": "4.0.0"}, {"fixed": "4.17.19"}]}],
            },
        ],
    }
    key = "npm/lodash@4.17.15"
    report_path = tmp_path / "report.json"
    with _patched_osv({key: {"GHSA-multi-0001"}}, {"GHSA-multi-0001": multi_range_record}):
        cli.run(["--file", str(lockfile), "--json", str(report_path)])

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report[0]["fixed_version"] == "4.17.19"


def test_run_writes_json_report(lockfile: Path, tmp_path: Path) -> None:
    key = "npm/lodash@4.17.15"
    report_path = tmp_path / "report.json"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(["--file", str(lockfile), "--json", str(report_path)])

    assert exit_code == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report[0]["vuln_id"] == "GHSA-high-0001"
    assert report[0]["severity"] == "HIGH"
    assert report[0]["fixed_version"] == "4.17.19"


def _run_git(args: list, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def test_run_diff_only_scans_only_changed_deps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(["init", "-b", "main"], repo)
    _run_git(["config", "user.email", "t@t.com"], repo)
    _run_git(["config", "user.name", "T"], repo)

    lockfile_path = repo / "package-lock.json"
    _write_npm_lockfile(lockfile_path, {"lodash": "4.17.15"})
    _run_git(["add", "package-lock.json"], repo)
    _run_git(["commit", "-m", "base"], repo)

    _write_npm_lockfile(lockfile_path, {"lodash": "4.17.15", "left-pad": "1.3.0"})
    _run_git(["add", "package-lock.json"], repo)
    _run_git(["commit", "-m", "add left-pad"], repo)

    monkeypatch.chdir(repo)
    captured = {}

    def _fake_batch_query(deps, session=None):
        captured["deps"] = deps
        return {}

    with (
        patch.object(cli.osv_client, "batch_query", side_effect=_fake_batch_query),
        patch.object(cli.osv_client, "hydrate_vulns", return_value={}),
    ):
        exit_code = cli.run(["--file", "package-lock.json", "--diff-only", "--base-ref", "HEAD~1"])

    assert exit_code == 0
    assert [d["name"] for d in captured["deps"]] == ["left-pad"]


def test_run_diff_only_multi_file_prints_per_file_diff_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(["init", "-b", "main"], repo)
    _run_git(["config", "user.email", "t@t.com"], repo)
    _run_git(["config", "user.name", "T"], repo)

    npm_path = repo / "package-lock.json"
    req_path = repo / "requirements.txt"
    _write_npm_lockfile(npm_path, {"lodash": "4.17.15"})
    req_path.write_text("requests==2.6.0\n", encoding="utf-8")
    _run_git(["add", "package-lock.json", "requirements.txt"], repo)
    _run_git(["commit", "-m", "base"], repo)

    _write_npm_lockfile(npm_path, {"lodash": "4.17.15", "left-pad": "1.3.0"})
    _run_git(["add", "package-lock.json"], repo)
    _run_git(["commit", "-m", "add left-pad"], repo)

    monkeypatch.chdir(repo)

    with (
        patch.object(cli.osv_client, "batch_query", return_value={}),
        patch.object(cli.osv_client, "hydrate_vulns", return_value={}),
    ):
        exit_code = cli.run(
            [
                "--file",
                "package-lock.json",
                "--file",
                "requirements.txt",
                "--diff-only",
                "--base-ref",
                "HEAD~1",
            ]
        )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Diff mode: package-lock.json: 1 new/changed dependency(ies) vs HEAD~1." in out
    assert "Diff mode: requirements.txt: 0 new/changed dependency(ies) vs HEAD~1." in out


def test_run_diff_only_multi_file_git_error_prints_per_file_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    non_repo = tmp_path / "not-a-repo"
    non_repo.mkdir()
    npm_path = non_repo / "package-lock.json"
    req_path = non_repo / "requirements.txt"
    _write_npm_lockfile(npm_path, {"lodash": "4.17.15"})
    req_path.write_text("requests==2.6.0\n", encoding="utf-8")
    monkeypatch.chdir(non_repo)

    def _raise_not_found(*args, **kwargs):
        raise FileNotFoundError("git not found")

    monkeypatch.setattr(subprocess, "run", _raise_not_found)

    exit_code = cli.run(
        [
            "--file",
            "package-lock.json",
            "--file",
            "requirements.txt",
            "--diff-only",
            "--base-ref",
            "HEAD~1",
        ]
    )

    assert exit_code == 2
    out = capsys.readouterr().out
    assert "Error computing diff for package-lock.json:" in out


def test_run_diff_only_outside_git_repo_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    non_repo = tmp_path / "not-a-repo"
    non_repo.mkdir()
    lockfile_path = non_repo / "package-lock.json"
    _write_npm_lockfile(lockfile_path, {"lodash": "4.17.15"})
    monkeypatch.chdir(non_repo)

    def _raise_not_found(*args, **kwargs):
        raise FileNotFoundError("git not found")

    monkeypatch.setattr(subprocess, "run", _raise_not_found)

    exit_code = cli.run(["--file", "package-lock.json", "--diff-only", "--base-ref", "HEAD~1"])

    assert exit_code == 2


def test_run_no_file_no_tty_exits_2_without_prompting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    # A scripted/CI invocation with no --file and no terminal to prompt on
    # must fail fast, never call input() and hang waiting on stdin.
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    def _input_should_not_be_called(*args, **kwargs):
        raise AssertionError("input() must not be called when stdin is not a tty")

    monkeypatch.setattr(builtins, "input", _input_should_not_be_called)

    exit_code = cli.run([])

    assert exit_code == 2
    assert "--file is required" in capsys.readouterr().out


def test_run_interactive_empty_input_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "   ")

    exit_code = cli.run([])

    assert exit_code == 2
    assert "no file path entered" in capsys.readouterr().out


def test_run_interactive_prompt_scans_the_entered_path(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: str(lockfile))

    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(["--fail-on", "high"])

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Enter path to lockfile to scan" in out
    assert "GATE BLOCKED" in out


def test_run_interactive_prompt_plain_output_path(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    # Same interactive flow, but the _RICH-unavailable branch: input() is
    # called with the prompt as its own argument instead of _console.print()
    # writing it first.
    monkeypatch.setattr(cli, "_RICH", False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: str(lockfile))

    key = "npm/lodash@4.17.15"
    with _patched_osv({key: {"GHSA-high-0001"}}, {"GHSA-high-0001": HIGH_VULN_RECORD}):
        exit_code = cli.run(["--fail-on", "high"])

    assert exit_code == 1
    assert "GATE BLOCKED" in capsys.readouterr().out


def test_run_interactive_prompt_splits_comma_separated_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    npm_file = tmp_path / "package-lock.json"
    py_file = tmp_path / "requirements.txt"
    _write_npm_lockfile(npm_file, {"lodash": "4.17.15"})
    py_file.write_text("requests==2.6.0\n", encoding="utf-8")

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: f" {npm_file} , {py_file} ")

    with (
        patch.object(cli.osv_client, "batch_query", return_value={}),
        patch.object(cli.osv_client, "hydrate_vulns", return_value={}),
    ):
        exit_code = cli.run([])

    assert exit_code == 0


def test_rich_unavailable_at_import_time_falls_back_to_plain_console(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # rich is imported inside a try/except ImportError at module load time
    # (cli.py:30-38) so the tool still runs, with plain print(), on a stray
    # environment missing it. Force that ImportError for real by blocking
    # the actual import machinery, then reload the module - rather than
    # just asserting on the already-imported state.
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich" or name.startswith("rich."):
            raise ImportError("simulated: rich not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    try:
        importlib.reload(cli)
        assert cli._RICH is False
        assert cli._console is None
    finally:
        # Restore the real import before reloading again, so the module
        # (shared across the whole test session) ends up back in its
        # normal rich-available state for every other test.
        monkeypatch.setattr(builtins, "__import__", real_import)
        importlib.reload(cli)

    assert cli._RICH is True


def test_module_entrypoint_invokes_run_and_exits_with_its_code() -> None:
    # Exercises `if __name__ == "__main__": sys.exit(run())` for real, via
    # the same `python -m dep_gate.cli` invocation the README documents -
    # not just calling run() directly, which never touches that line.
    result = subprocess.run(
        [sys.executable, "-m", "dep_gate.cli", "--help"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "usage: dep-gate" in result.stdout
