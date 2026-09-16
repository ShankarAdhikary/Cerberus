"""
GitHub API client for the opt-in `--pr-comment` feature: posts/updates a
single idempotent PR comment summarizing blocking findings.

This is the tool's SECOND network egress point, after osv_client.py - see
PRD.md's zero-telemetry NFR, which scopes any egress beyond api.osv.dev to
"the GitHub API for PR comments the user explicitly enables". It must
never be called unless the user passed --pr-comment; cli.py enforces
that, not this module.

Auth model: the workflow's own GITHUB_TOKEN with job-scoped
`permissions: pull-requests: write`, not a GitHub App - see Tracker.md's
"Resolved decisions" for the rationale (this is a single-repo PR-gate
tool; a GitHub App adds infrastructure PRD.md's NFRs explicitly reject).
"""

from __future__ import annotations

import time
from typing import Any

import requests

API_BASE = "https://api.github.com"
REQUEST_TIMEOUT = 15
MAX_RETRIES = 3
BACKOFF_BASE = 1.0  # seconds, doubles-ish each retry

# Marks our own comment so upsert_comment() can find and update it on a
# re-run instead of posting a new comment every push - Design.md §4's
# idempotency rule.
COMMENT_MARKER = "<!-- dep-gate-pr-comment -->"

_EMOJI_BY_SEVERITY = {"CRITICAL": "🔴", "HIGH": "🟠", "MODERATE": "🟡", "LOW": "🔵"}


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _request_with_retries(
    session: requests.Session, method: str, url: str, **kwargs: Any
) -> requests.Response:
    """
    Same retry/backoff shape as osv_client.py's _request_with_retries, so a
    transient GitHub API hiccup or secondary rate limit doesn't immediately
    surface as a (non-blocking, but noisy) "failed to post PR comment"
    warning. Honors GitHub's `Retry-After` response header when present
    (GitHub returns this on secondary rate limits) in preference to the
    fixed backoff schedule.
    """
    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            resp = session.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
            if resp.status_code == 429 or resp.status_code >= 500:
                raise requests.HTTPError(f"Retryable status {resp.status_code}", response=resp)
            resp.raise_for_status()
            return resp
        except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as exc:
            last_exc = exc
            retry_after = getattr(getattr(exc, "response", None), "headers", {}).get("Retry-After")
            sleep_for = float(retry_after) if retry_after else BACKOFF_BASE * (2**attempt)
            time.sleep(sleep_for)
    raise RuntimeError(f"GitHub API request failed after {MAX_RETRIES} attempts: {last_exc}")


def _findings_table(findings: list[dict[str, Any]]) -> list[str]:
    rows = ["| Severity | Package | Vuln ID | Fix |", "|---|---|---|---|"]
    for f in findings:
        emoji = _EMOJI_BY_SEVERITY.get(f["severity"], "")
        fix = f"Upgrade to `{f['fixed_version']}`" if f.get("fixed_version") else "no fix yet"
        rows.append(
            f"| {emoji} {f['severity']} | `{f['package']}@{f['version']}` | "
            f"{f['vuln_id']} | {fix} |"
        )
    return rows


def render_pr_comment(
    blocking: list[dict[str, Any]],
    scanned: list[tuple[str, int]],
    fail_on: str,
    diff_mode: bool,
    base_ref: str | None,
) -> str:
    """
    Render the Markdown PR comment body per Design.md §4. Pure function,
    no I/O - shows only *blocking* findings above the fold (not every
    LOW/UNKNOWN finding), and never includes a raw CVSS vector string,
    per that same design rule.

    `scanned` is one `(file_path, dependency_count)` pair per lockfile
    scanned. With exactly one entry, the comment renders exactly as it
    did before multi-file support existed - a single flat table, a single
    "Scanned: N dependencies" line - since that's the single-file case
    this project's byte-compat contract covers. With more than one entry,
    blocking findings are grouped under a "### `file`" subheading each
    (via each finding's own `source_file`, which `cli.py` only sets in
    the multi-file case) so a PR touching two lockfiles doesn't lose
    which file a given row came from, and the scan-details line lists
    every file's own count.
    """
    if blocking:
        result_line = f"**Result:** ❌ Failed — {len(blocking)} finding(s) at or above `{fail_on}`"
    else:
        result_line = f"**Result:** ✅ Passed — no finding(s) at or above `{fail_on}`"

    lines = [
        "## 🔒 Dependency Vulnerability Gate",
        "",
        result_line,
        "",
    ]

    if blocking:
        if len(scanned) > 1:
            by_file: dict[str, list[dict[str, Any]]] = {}
            for f in blocking:
                by_file.setdefault(f.get("source_file", ""), []).append(f)
            for file_path, file_findings in by_file.items():
                lines.append(f"### `{file_path}`")
                lines.append("")
                lines += _findings_table(file_findings)
                lines.append("")
        else:
            lines += _findings_table(blocking)
            lines.append("")

    if len(scanned) > 1:
        scanned_desc = "Scanned: " + ", ".join(
            f"`{file_path}` ({count} dependencies)" for file_path, count in scanned
        )
    else:
        _file_path, count = scanned[0]
        scanned_desc = f"Scanned: {count} dependencies"
    if diff_mode:
        scanned_desc += f" (diff-only vs `{base_ref}`)"

    lines += [
        "<details>",
        "<summary>Scan details</summary>",
        "",
        f"- {scanned_desc}",
        f"- Threshold: `--fail-on {fail_on}`",
        "- Full report: see the `dependency-vulnerability-report` build artifact",
        "",
        "</details>",
    ]

    return COMMENT_MARKER + "\n" + "\n".join(lines)


def find_existing_comment_id(
    repo: str, pr_number: int, token: str, session: requests.Session | None = None
) -> int | None:
    """Find our own bot comment on this PR (identified by COMMENT_MARKER), if any."""
    session = session or requests.Session()
    url = f"{API_BASE}/repos/{repo}/issues/{pr_number}/comments"
    resp = _request_with_retries(session, "GET", url, headers=_headers(token))
    for comment in resp.json():
        if COMMENT_MARKER in comment.get("body", ""):
            return comment["id"]
    return None


def upsert_comment(
    repo: str, pr_number: int, body: str, token: str, session: requests.Session | None = None
) -> None:
    """Create the bot's findings comment on a PR, or update it in place if one already exists."""
    session = session or requests.Session()
    existing_id = find_existing_comment_id(repo, pr_number, token, session=session)

    headers = _headers(token)
    payload = {"body": body}
    if existing_id is not None:
        url = f"{API_BASE}/repos/{repo}/issues/comments/{existing_id}"
        _request_with_retries(session, "PATCH", url, headers=headers, json=payload)
    else:
        url = f"{API_BASE}/repos/{repo}/issues/{pr_number}/comments"
        _request_with_retries(session, "POST", url, headers=headers, json=payload)
