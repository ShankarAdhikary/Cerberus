"""
Dependency Vulnerability Gate - CLI entry point.

Usage:
    python -m dep_gate.cli --file package-lock.json --fail-on high
    python -m dep_gate.cli --file requirements.txt --fail-on critical --json report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import cache as cache_module
from . import diff as diff_module
from . import github_client, lockfile, osv_client, severity
from . import sarif as sarif_module
from . import sbom as sbom_module
from . import suppress as suppress_module

THRESHOLD_ORDER = ["low", "moderate", "high", "critical"]

try:
    from rich.console import Console
    from rich.table import Table

    _console = Console()
    _RICH = True
except ImportError:  # rich is optional - degrade to plain print()
    _console = None
    _RICH = False


def _print(msg: str = "") -> None:
    if _RICH:
        _console.print(msg)
    else:
        print(msg)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-gate",
        description="Scan a lockfile for known vulnerabilities via OSV.dev and gate CI on the result.",
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to package-lock.json, requirements.txt, go.sum, or Cargo.lock",
    )
    parser.add_argument(
        "--fail-on",
        choices=THRESHOLD_ORDER,
        default="high",
        help="Minimum severity that fails the build (default: high)",
    )
    parser.add_argument(
        "--json", metavar="PATH", help="Also write a machine-readable JSON report to PATH"
    )
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        help="Also write a SARIF 2.1.0 report to PATH for GitHub code-scanning upload "
        "(github/codeql-action/upload-sarif). Same findings as --json, different shape.",
    )
    parser.add_argument(
        "--sbom",
        metavar="PATH",
        help="Also write a CycloneDX JSON Software Bill of Materials to PATH, listing "
        "every dependency that was scanned (respects --diff-only). Independent of "
        "vulnerability findings - written even on a clean scan.",
    )
    parser.add_argument(
        "--fail-open",
        action="store_true",
        help="If the OSV API is unreachable, exit 0 (pass) instead of failing the build. "
        "Off by default: a broken security gate should be loud, not silent.",
    )
    parser.add_argument(
        "--diff-only",
        action="store_true",
        help="Only scan dependencies that are new or version-changed relative to --base-ref, "
        "instead of the whole lockfile. Requires a git repo with --base-ref fetched.",
    )
    parser.add_argument(
        "--base-ref",
        default="origin/main",
        help="Git ref to diff against when --diff-only is set (default: origin/main). "
        "In GitHub Actions, use 'origin/${{ github.base_ref }}' and check out with fetch-depth: 0.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include how each severity rating was derived (Severity.source, e.g. "
        "'CVSS_V3 vector' or 'database_specific.severity') as an extra column in the "
        "table and an extra field in the JSON report. Off by default to keep both "
        "outputs uncluttered.",
    )
    parser.add_argument(
        "--ignore-file",
        metavar="PATH",
        help="Path to a .dep-gate-ignore.yml suppression file (vuln_id, optional package, "
        "required expires date and reason per entry). A matching, non-expired entry "
        "excludes that finding from the --fail-on threshold check without hiding it "
        "from the table/JSON output - suppressions are auditable, never silent. An "
        "expired entry stops suppressing automatically.",
    )
    parser.add_argument(
        "--cache-file",
        metavar="PATH",
        help="Path to a local JSON cache of hydrated OSV vuln records, reused across runs "
        "(e.g. across CI jobs in the same repo, via actions/cache) to skip re-fetching "
        "vuln IDs already fetched within the last "
        f"{cache_module.CACHE_TTL_SECONDS // 3600} hours. Off by default - always fetches "
        "fresh when not set.",
    )
    parser.add_argument(
        "--pr-comment",
        action="store_true",
        help="Post/update an idempotent PR comment summarizing blocking findings, via the "
        "GitHub API. Off by default - this is the tool's second network egress point (see "
        "PRD.md's zero-telemetry NFR). Requires --github-repo, --github-pr-number, and a "
        "GITHUB_TOKEN environment variable (never passed as a CLI argument, to keep it out "
        "of process listings/CI logs).",
    )
    parser.add_argument(
        "--github-repo",
        metavar="OWNER/REPO",
        help="Repository to comment on. Required with --pr-comment.",
    )
    parser.add_argument(
        "--github-pr-number",
        type=int,
        metavar="N",
        help="Pull request number to comment on. Required with --pr-comment.",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    pr_comment_token = os.environ.get("GITHUB_TOKEN", "")
    if args.pr_comment and (
        not args.github_repo or not args.github_pr_number or not pr_comment_token
    ):
        _print(
            "Error: --pr-comment requires --github-repo, --github-pr-number, and a "
            "GITHUB_TOKEN environment variable."
        )
        return 2

    try:
        if args.diff_only:
            deps = diff_module.diff_dependencies(args.file, args.base_ref)
            _print(f"Diff mode: {len(deps)} new/changed dependency(ies) vs {args.base_ref}.")
        else:
            deps = lockfile.parse_lockfile(args.file)
    except (FileNotFoundError, ValueError) as exc:
        _print(f"Error reading {args.file}: {exc}")
        return 2
    except diff_module.GitDiffError as exc:
        _print(f"Error computing diff: {exc}")
        return 2

    suppressions: list[suppress_module.Suppression] = []
    if args.ignore_file:
        try:
            suppressions = suppress_module.load_suppressions(args.ignore_file)
        except (FileNotFoundError, ValueError) as exc:
            _print(f"Error reading {args.ignore_file}: {exc}")
            return 2

    if args.sbom:
        with open(args.sbom, "w", encoding="utf-8") as f:
            json.dump(sbom_module.build_sbom(deps), f, indent=2)

    if not deps:
        _print("No dependencies found to scan.")
        return 0

    _print(f"Scanning {len(deps)} dependencies against OSV.dev ...")

    now = time.time()
    cache = cache_module.load_cache(args.cache_file) if args.cache_file else {}

    try:
        matches = osv_client.batch_query(deps)
        all_vuln_ids = {vid for ids in matches.values() for vid in ids}

        hydrated: dict = {}
        to_fetch = all_vuln_ids
        if args.cache_file:
            hydrated = {
                vid: record
                for vid in all_vuln_ids
                if (record := cache_module.get_fresh(cache, vid, now)) is not None
            }
            to_fetch = all_vuln_ids - hydrated.keys()

        if to_fetch:
            freshly_fetched = osv_client.hydrate_vulns(to_fetch)
            hydrated.update(freshly_fetched)
            if args.cache_file:
                for vid, record in freshly_fetched.items():
                    cache_module.put(cache, vid, record, now)
                cache_module.save_cache(args.cache_file, cache)
    except RuntimeError as exc:
        _print(f"OSV API error: {exc}")
        return 0 if args.fail_open else 1

    findings = []
    dep_by_key = {f"{d['ecosystem']}/{d['name']}@{d['version']}": d for d in deps}

    for key, vuln_ids in matches.items():
        dep = dep_by_key[key]
        for vid in vuln_ids:
            record = hydrated.get(vid, {})
            sev = severity.assess(record)
            fix = severity.fixed_version(
                record, dep["ecosystem"], dep["name"], installed_version=dep["version"]
            )
            finding = {
                "package": dep["name"],
                "version": dep["version"],
                "ecosystem": dep["ecosystem"],
                "vuln_id": vid,
                "severity": sev.level,
                "cvss_score": sev.score,
                "fixed_version": fix,
                "summary": record.get("summary", ""),
            }
            if args.verbose:
                finding["source"] = sev.source
            if args.ignore_file:
                match = suppress_module.find_active_suppression(vid, dep["name"], suppressions)
                finding["suppressed"] = match is not None
                finding["suppression_reason"] = match.reason if match else None
            findings.append(finding)

    _report(findings, verbose=args.verbose)

    suppressed_findings = [f for f in findings if f.get("suppressed")]
    if suppressed_findings:
        _print(
            f"Suppressed (not blocking): {len(suppressed_findings)} finding(s) via "
            f"{args.ignore_file}."
        )

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as f:
            json.dump(sarif_module.build_sarif(findings, args.file), f, indent=2)

    threshold_idx = THRESHOLD_ORDER.index(args.fail_on)
    blocking = [
        f
        for f in findings
        if not f.get("suppressed")
        and f["severity"].lower() in THRESHOLD_ORDER
        and THRESHOLD_ORDER.index(f["severity"].lower()) >= threshold_idx
    ]

    if args.pr_comment:
        body = github_client.render_pr_comment(
            blocking=blocking,
            scanned_count=len(deps),
            fail_on=args.fail_on,
            diff_mode=args.diff_only,
            base_ref=args.base_ref if args.diff_only else None,
        )
        try:
            github_client.upsert_comment(
                args.github_repo, args.github_pr_number, body, pr_comment_token
            )
        except Exception as exc:  # noqa: BLE001
            # Deliberately broad: a comment-posting failure (network error, bad
            # token, rate limit, ...) must never change the scan's own pass/fail
            # result - see AppFlow.md §4's "additive output, not a replacement" rule.
            _print(f"Warning: failed to post PR comment: {exc}")

    if blocking:
        _print(f"\nSCAN FAILED: {len(blocking)} finding(s) at or above '{args.fail_on}'.")
        return 1

    _print("\nSCAN PASSED: no findings at or above the configured threshold.")
    return 0


def _report(findings: list, verbose: bool = False) -> None:
    if not findings:
        return
    if _RICH:
        table = Table(title="Dependency Vulnerability Findings")
        table.add_column("Package")
        table.add_column("Version")
        table.add_column("Severity")
        table.add_column("Vuln ID")
        table.add_column("Fix")
        if verbose:
            table.add_column("Source")
        for f in sorted(findings, key=lambda x: x["severity"], reverse=True):
            severity_cell = f["severity"] + (" (suppressed)" if f.get("suppressed") else "")
            row = [
                f["package"],
                f["version"],
                severity_cell,
                f["vuln_id"],
                f"upgrade to {f['fixed_version']}" if f["fixed_version"] else "no fix yet",
            ]
            if verbose:
                row.append(f.get("source", ""))
            table.add_row(*row)
        _console.print(table)
    else:
        for f in findings:
            fix_msg = (
                f"upgrade to {f['fixed_version']}" if f["fixed_version"] else "no fix published yet"
            )
            severity_text = f["severity"] + (" (suppressed)" if f.get("suppressed") else "")
            line = f"[{severity_text}] {f['package']}@{f['version']} - {f['vuln_id']} - {fix_msg}"
            if verbose:
                line += f" (source: {f.get('source', '')})"
            print(line)


if __name__ == "__main__":
    sys.exit(run())
