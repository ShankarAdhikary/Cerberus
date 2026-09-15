# Tracker.md — Task Tracker

Aligned 1:1 with `ImplementationPlan.md`. Check off items only when the
corresponding phase's "Exit criteria" are fully met, including tests —
not when the code merely runs once locally.

## Done

- [x] Scaffold `dep_gate/` package (`__init__.py`)
- [x] Implement `parse_npm_lockfile()` (v1/v2/v3, transitive deps)
- [x] Implement `parse_requirements_txt()` (pinned `==` lines, warn on skip)
- [x] Implement `parse_lockfile()` dispatch function
- [x] Implement `_dedupe()` by `(ecosystem, name, version)`
- [x] Implement `batch_query()` against `POST /v1/querybatch`
- [x] Implement `hydrate_vulns()` against `GET /v1/vulns/{id}`
- [x] Implement `_request_with_retries()` shared backoff wrapper
- [x] Implement `severity.assess()` (CVSS vector → `database_specific` → `UNKNOWN` precedence)
- [x] Implement `severity.fixed_version()` (package-scoped fix lookup)
- [x] Implement `argparse` CLI with `--file`, `--fail-on`, `--json`, `--fail-open`
- [x] Implement `run()` orchestration with correct exit codes (0/1/2)
- [x] Implement Rich findings table with optional plain-text fallback
- [x] Implement grep-able `SCAN FAILED` / `SCAN PASSED` summary line
- [x] Implement `diff.get_base_dependencies()` via `git show` subprocess
- [x] Implement `diff.diff_dependencies()` set-diff logic
- [x] Wire `--diff-only` / `--base-ref` into `cli.run()`
- [x] Write `.github/workflows/security-scan.yml` with `fetch-depth: 0`
- [x] End-to-end manual verification: mocked-OSV CLI run, real temp-git-repo diff test
- [x] Formalize `unittest`/`pytest` test suite under `tests/` (59 tests: lockfile.py, severity.py, osv_client.py mocked-`requests.Session`, diff.py real temp-dir git repo, cli.py end-to-end with only the osv_client boundary mocked — see verification pass recorded below)
- [x] Fix `diff.get_base_dependencies()` treating every non-zero `git show` exit as "file absent at ref" — now raises `GitDiffError` for an unresolvable ref / non-repo per TechSpec.md §4, only returns `[]` for a genuinely-absent path at a resolvable ref (regression tests in `tests/test_diff.py`)
- [x] Fix `severity.fixed_version()` picking the lexicographically-lowest fix string (e.g. "4.17.19" < "4.17.2") instead of the numerically-lowest version — added `_version_sort_key()` natural-sort helper (regression tests in `tests/test_severity.py`)
- [x] Add `Go` ecosystem support: `parse_go_sum()` (`go.sum` → `ecosystem="Go"` deps, content-hash/`/go.mod`-hash rows collapsed via dedupe), wired into `parse_lockfile()` dispatch, `--file` help text, and `.github/workflows/security-scan.yml`'s go.sum scan step; docs updated (PRD.md moved it V2→V1, TechSpec.md §2.1, README.md)
- [x] Add `Rust` ecosystem support: `parse_cargo_lock()` (`Cargo.lock` TOML via stdlib `tomllib` → `ecosystem="crates.io"` deps, registry-only — path/git deps skipped), wired into `parse_lockfile()` dispatch, `--file` help text, and `.github/workflows/security-scan.yml`'s Cargo.lock scan step; docs updated (PRD.md moved it V2→V1, TechSpec.md §2.1, README.md); no new third-party dependency (`tomllib` is stdlib on the project's Python 3.11+ baseline)
- [x] Fix `severity.fixed_version()` recommending a downgrade when one OSV record covers multiple disjoint vulnerable ranges for the same package (confirmed live via GHSA-43w2-9j62-hq99/RUSTSEC-2021-0003 — smallvec@crates.io) — added optional `installed_version` param so only the range actually containing the installed version is used; wired through from `cli.run()`; docs updated (Schema.md §5.3, TechSpec.md §2.3); regression tests in `tests/test_severity.py` and `tests/test_cli.py`
- [x] Add `--verbose` flag surfacing `Severity.source` — purely additive: extra "Source" table column (Rich + plain-text) and extra `"source"` JSON field, both omitted by default; does not change severity, fix recommendation, or exit code. Docs updated (AppFlow.md flags table, Design.md §3.2, Schema.md `Vulnerability`/`Severity`, README.md); tests in `tests/test_cli.py`
- [x] Add SBOM export: new `sbom.py` module (`build_sbom()`, pure/I-O free, ecosystem→purl-type mapping), `--sbom PATH` flag writes a CycloneDX 1.5 JSON document from whichever dependency list was scanned (respects `--diff-only`), independent of vulnerability findings — written even on a clean scan or OSV.dev outage, not written on a usage error. Not wired into the PR-gate CI workflow (would only ever produce a partial/delta SBOM there — documented in README.md instead). Docs updated (TechSpec.md §1/§2.5, AppFlow.md flags table + execution tree, PRD.md, README.md); tests in `tests/test_sbom.py` and `tests/test_cli.py`
- [x] Add `.dep-gate-ignore.yml` suppression-file support: new `suppress.py` module (`load_suppressions()`/`find_active_suppression()`, hand-rolled minimal parser for a deliberately narrow YAML-list-of-mappings subset — no new `PyYAML` dependency), `--ignore-file PATH` flag; required `vuln_id`/`expires`/`reason` per entry (missing/blank → exit 2), optional `package` scoping, expiry enforced automatically (string-comparable ISO dates). Suppressed findings stay visible (`SEVERITY (suppressed)`) and are excluded only from the `--fail-on` `blocking` check, never hidden — live-verified against real OSV.dev data. Docs updated (PRD.md moved it V2→V1, AppFlow.md flags table/degradation table/execution tree, Design.md, Schema.md §3.5, TechSpec.md §1/§2.6, README.md); tests in `tests/test_suppress.py` and `tests/test_cli.py`
- [x] Add local hydration cache: new `cache.py` module (`load_cache()`/`save_cache()`/`get_fresh()`/`put()`, flat JSON keyed by vuln_id, `CACHE_TTL_SECONDS=6h`, corrupt/missing cache file treated as empty rather than crashing), `--cache-file PATH` flag; deliberately TTL-based rather than using OSV's per-result `modified` timestamp, to avoid changing `batch_query()`'s tested return shape (reasoning recorded in TechSpec.md §2.8, superseding Schema.md §5.1's earlier speculative note). Without `--cache-file`, behavior is byte-for-byte unchanged from before. Wired into `.github/workflows/security-scan.yml` via `actions/cache` (restore-keys prefix pattern) — **not exercised against a live GitHub Actions run** (same caveat as the SARIF upload step). Live-verified locally: cold run populated 6 cache entries from real OSV.dev data; warm run reused them (same findings, same exit code, ~3.4x faster); CLI-level tests assert zero `hydrate_vulns()` calls on a full cache hit and correct re-fetch of expired entries. Docs updated (PRD.md moved it to V1, AppFlow.md flags table + execution tree, Schema.md §5.1, TechSpec.md §1/§2.8, README.md); tests in `tests/test_cache.py` and `tests/test_cli.py`
- [x] Add SARIF output: new `sarif.py` module (`build_sarif()`, pure/I-O free, rule dedup by vuln_id, severity→SARIF-level mapping CRITICAL/HIGH→error, MODERATE→warning, LOW/UNKNOWN→note, whole-file locations, suppressed findings marked via SARIF's native `result.suppressions` rather than omitted), `--sarif PATH` flag alongside (not instead of) `--json`, not written on a usage error. Wired into `.github/workflows/security-scan.yml` (added `security-events: write` permission + `github/codeql-action/upload-sarif@v3` step, `continue-on-error: true` so an upload failure can't mask a real scan failure) — **this workflow wiring has not been exercised against a live GitHub Actions run in this session** (no live repo/Actions environment available), unlike the SARIF document shape itself, which was live-verified against real OSV.dev findings. Docs updated (PRD.md moved it to V1, AppFlow.md flags table + execution tree, TechSpec.md §1/§2.7); tests in `tests/test_sarif.py` and `tests/test_cli.py`
- [x] Add GitHub PR auto-commenting: new `github_client.py` module (the tool's second and only other network egress point besides `osv_client.py`) — `render_pr_comment()` (pure, renders Design.md §4's exact structure, blocking-findings-only, never a raw CVSS vector), `find_existing_comment_id()`/`upsert_comment()` (mocked-`requests.Session`-tested, same pattern as `osv_client.py`) using a hidden `COMMENT_MARKER` for idempotent per-PR updates. `--pr-comment`/`--github-repo`/`--github-pr-number` flags; token read from a `GITHUB_TOKEN` env var only (never a CLI argument, to keep it out of process listings/CI logs); required-args validation happens first, right after argument parsing, before any OSV.dev call (fail fast on a usage error, exit 2); a comment-posting failure prints a warning but never changes the scan's own exit code. **Auth model resolved** (was Blocked): `GITHUB_TOKEN` with job-scoped `permissions: pull-requests: write`, not a GitHub App — this is a single-repo PR-gate tool, and a GitHub App would add registration/installation/secret-management infrastructure that PRD.md's own NFRs reject ("doesn't require standing up new infrastructure" — DevOps persona); `GITHUB_TOKEN` is the standard zero-setup pattern for this exact idempotent-bot-comment use case. **Deliberately not wired into `.github/workflows/security-scan.yml`**: that workflow scans up to four lockfiles in separate steps, and each `--pr-comment` invocation would find-and-overwrite the same idempotent comment, leaving it reflecting only the last ecosystem scanned — worse than no comment. A correct combined comment needs one invocation across all changed lockfiles, out of scope for the current one-file-per-invocation `cli.py` design; documented (not silently dropped) in README.md with a single-lockfile usage example instead. **Not exercised against the real GitHub API** in this session (no live repo/PR/token available) — `render_pr_comment()` was live-verified against real, previously-confirmed OSV.dev findings data (matches Design.md §4 exactly), but `find_existing_comment_id()`/`upsert_comment()` are mocked-only; treat the live GitHub integration as unverified until run for real. Docs updated (PRD.md moved it to V1 + zero-telemetry NFR, TechSpec.md §1/§2.9, AppFlow.md flags table/execution tree/degradation table/§4, Design.md §4, README.md); tests in `tests/test_github_client.py` and `tests/test_cli.py`

## To Do

- [ ] *(none currently — all PRD.md V1 items implemented and tested)*

## In Progress

- [ ] *(none currently — update this section when work starts)*

## Blocked

- [ ] *(none currently)*

## Notes for Agents Updating This Tracker

- Move an item from **To Do** → **In Progress** the moment you start
  editing files for it, not after you finish — this file should reflect
  real-time state, not be reconstructed after the fact.
- Never mark an item **Done** without a corresponding test existing in
  the repo for it (see `Rules.md`).
- If an item turns out to need a decision or external input before it
  can proceed, move it to **Blocked** with a one-line reason, don't leave
  it silently stuck in **In Progress**.
