# AppFlow.md — Execution Flow

## 1. CLI Arguments & Flags

Invocation: `python -m dep_gate.cli [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--file` | str, required | — | Path to `package-lock.json`, `requirements.txt`, `go.sum`, or `Cargo.lock`. |
| `--fail-on` | choice | `high` | Minimum severity (`low`, `moderate`, `high`, `critical`) that produces exit code `1`. |
| `--json` | str, optional | none | Path to write a machine-readable JSON report. |
| `--sbom` | str, optional | none | Path to write a CycloneDX JSON SBOM of every dependency scanned (respects `--diff-only`). Independent of findings - written even on a clean scan or an OSV.dev outage, not written on a usage error (exit 2). |
| `--sarif` | str, optional | none | Path to write a SARIF 2.1.0 report (same findings as `--json`, a different shape) for `github/codeql-action/upload-sarif`. Not written on a usage error (exit 2). |
| `--cache-file` | str, optional | none | Path to a local JSON cache of hydrated OSV records, reused across runs (e.g. via `actions/cache` in CI) to skip re-fetching a vuln ID already fetched within `CACHE_TTL_SECONDS` (6h). Off by default — always fetches fresh. |
| `--fail-open` | flag | off | If OSV.dev is unreachable after retries, exit `0` instead of `1`. |
| `--diff-only` | flag | off | Scan only dependencies new/changed vs. `--base-ref`. |
| `--base-ref` | str | `origin/main` | Git ref to diff against when `--diff-only` is set. |
| `--verbose` | flag | off | Include `Severity.source` (how each rating was derived) as an extra table column and JSON field. Off by default; does not change severity, exit code, or any other field. |
| `--ignore-file` | str, optional | none | Path to a `.dep-gate-ignore.yml` suppression file. A matching, non-expired entry excludes that finding from the `--fail-on` check without hiding it (shown as `SEVERITY (suppressed)`); an expired entry blocks normally. Malformed file → exit 2. |
| `--pr-comment` | flag | off | Post/update an idempotent PR comment (via `github_client.py`, the tool's second and only other network egress point) summarizing *blocking* findings. Requires `--github-repo`, `--github-pr-number`, and a `GITHUB_TOKEN` env var (missing any → exit 2). A posting failure prints a warning but never changes the exit code. |
| `--github-repo` | str | none | `OWNER/REPO` to comment on. Required with `--pr-comment`. |
| `--github-pr-number` | int | none | PR number to comment on. Required with `--pr-comment`. |

V2 additions (not yet implemented, reserved names): `--ecosystem`
(restrict scanning to one ecosystem when a file could be ambiguous).

## 2. Execution Tree

```
main()
└── run(argv)
    ├── parse args (argparse)
    │
    ├── [--pr-comment set, missing --github-repo / --github-pr-number / GITHUB_TOKEN]
    │     → print, exit 2 (checked first - fail fast before any OSV.dev call)
    │
    ├── [IF --diff-only]
    │   ├── diff.diff_dependencies(file, base_ref)
    │   │     ├── parse_lockfile(file)                → current deps
    │   │     ├── get_base_dependencies(file, base_ref) → base deps (git show)
    │   │     │     └── [file absent at base_ref] → return [] (not an error)
    │   │     └── set-diff by (ecosystem, name, version) → new/changed deps
    │   └── [git missing] → raise GitDiffError → print, exit 2
    │
    ├── [ELSE]
    │   └── lockfile.parse_lockfile(file) → all deps
    │       └── [malformed / unrecognized file] → catch ValueError/FileNotFoundError
    │                                              → print, exit 2
    │
    ├── [--ignore-file PATH set] → suppress.load_suppressions(PATH)
    │     └── [missing file / missing field / bad date] → print, exit 2
    │
    ├── [--sbom PATH set] → sbom.build_sbom(deps) → write PATH
    │     (whichever deps list was resolved above - full or diff-only;
    │      not reached on the exit-2 paths above, since deps was never
    │      resolved there)
    │
    ├── [deps is empty] → print "No dependencies found", exit 0
    │
    ├── osv_client.batch_query(deps)
    │     └── [network/API failure after retries] → raise RuntimeError
    │            ├── --fail-open set   → print warning, exit 0
    │            └── --fail-open unset → print error, exit 1  (fail-closed default)
    │
    ├── [--cache-file PATH set] → cache.load_cache(PATH); split unique_vuln_ids
    │     into fresh-cache-hits (skip fetch) vs. misses (still fetch below)
    │
    ├── osv_client.hydrate_vulns(missing_vuln_ids)  [only the cache misses,
    │   │                                            or all of them if --cache-file unset]
    │     └── (same failure handling as above; both calls share one try/except)
    │
    ├── [--cache-file PATH set] → cache.put() each freshly-fetched record,
    │     cache.save_cache(PATH)  (fresh cache-hit entries' timestamps untouched)
    │
    ├── for each (dependency, vuln_id) pair:
    │     ├── severity.assess(hydrated_record)      → Severity(level, score, source)
    │     ├── severity.fixed_version(record, ...)   → Optional[str]
    │     └── [--ignore-file set] → suppress.find_active_suppression(...) →
    │           mark finding's `suppressed`/`suppression_reason` (not marked when unset)
    │     → append to findings[]
    │
    ├── _report(findings)               → Rich table, or plain-text lines if Rich unavailable
    │
    ├── [--json set] → write findings to JSON file
    ├── [--sarif PATH set] → sarif.build_sarif(findings, file) → write PATH
    │
    ├── compute `blocking` = non-suppressed findings at/above --fail-on threshold
    │
    ├── [--pr-comment set]  (required-args check already passed above)
    │   ├── github_client.render_pr_comment(blocking, ...) → body
    │   └── github_client.upsert_comment(repo, pr_number, body, token)
    │         └── [posting fails] → print warning only - never changes the exit code below
    │
    └── [blocking non-empty] → print failure summary, exit 1
        [blocking empty]     → print pass summary, exit 0
```

## 3. Graceful Degradation Paths

| Failure scenario | Behavior |
|---|---|
| Lockfile doesn't exist, or is unparseable JSON/text | Caught in `run()`, printed as a clear error, exit code `2` (tool/usage error — distinct from a security failure). |
| Lockfile has zero dependencies | Not an error; prints a notice and exits `0`. |
| OSV.dev API is down or times out | Retried with backoff inside `osv_client.py`; if still failing, `run()` decides exit `0` (only with explicit `--fail-open`) or `1` (default). Never silently passes without printing a warning either way. |
| A vulnerability record has no `severity[]` and no `database_specific.severity` | `severity.assess()` returns `Severity("UNKNOWN", None, "no severity data")`. `UNKNOWN` is never treated as blocking by the `--fail-on` comparison (it doesn't appear in `THRESHOLD_ORDER`), so it's reported but does not fail the build — visibility without false-positive noise. |
| `--diff-only` requested outside a git repo, or `git` not installed | `diff.py` raises `GitDiffError`; `run()` catches it, prints a clear message distinct from a generic parse error, exit code `2`. |
| `--ignore-file` points to a missing file, or an entry is missing `vuln_id`/`expires`/`reason`, has a blank `reason`, or an unparseable `expires` date | `suppress.load_suppressions()` raises `FileNotFoundError`/`ValueError`; `run()` catches it, prints a clear message, exit code `2` — a suppression tool that tolerates malformed entries by ignoring them would fail open. |
| `--ignore-file` entry's `expires` date is in the past | Not an error; the entry simply no longer matches in `find_active_suppression()`, so that finding blocks normally again — expiry is enforced automatically, not just documented. |
| `--diff-only` requested but the lockfile is brand new (didn't exist at `--base-ref`) | Not an error — `get_base_dependencies()` returns `[]`, so every dependency in the new file is treated as "new" and scanned normally. |
| `rich` is not installed in the environment | `cli.py`'s `_RICH` flag flips to `False` at import time; all output falls back to plain `print()` with identical information content, just without table formatting. |
| A CVSS vector string is malformed or uses an unsupported CVSS major version | `severity._score_from_vector()` catches the parse exception internally and returns `None` for that entry rather than raising — evaluation falls through to the `database_specific.severity` fallback or `UNKNOWN`. |
| `--pr-comment` set without `--github-repo`/`--github-pr-number`/`GITHUB_TOKEN` | Checked first, right after argument parsing (before any OSV.dev call); prints a clear message, exit code `2`. |
| `--pr-comment`'s GitHub API call fails (network error, bad token, rate limit) | Caught in `run()`, printed as a warning; never changes the scan's own exit code — a comment-posting failure is not a security-relevant failure. |

## 4. Non-Interactive Design Constraint

This is a CI-first tool: it must never block on stdin, must never require
a TTY (Rich must render acceptably to a redirected log file, not just a
terminal), and must produce all of its decision-relevant output (pass/fail,
findings) to stdout/stderr plus the optional `--json` file — never only to
an interactive widget. `--pr-comment` is additive output on top of that,
not a replacement for it — the terminal/JSON/SARIF report is always
produced regardless of whether `--pr-comment` is set or whether posting
the comment succeeds.
