# ImplementationPlan.md — Phased Build Sequence

Each phase is self-contained and independently testable. An AI coding
agent should complete and verify one phase fully (including its tests)
before starting the next — do not begin Phase N+1 work while Phase N has
open failing tests or unresolved TODOs (see `Rules.md`).

> **Status note:** Phases 1–3 and part of Phase 4/5 (delta scanning, CI
> wrapper) are already implemented in this repository as of this
> document's writing. This plan is written as if starting from zero so
> it remains valid as a reference for re-implementation, forks, or
> porting to a new ecosystem.

## Phase 1 — Setup & Lockfile Parser
**Goal:** A tested, network-free module that turns a lockfile into a
clean `List[Dependency]`.

1. Scaffold the `dep_gate/` package with `__init__.py`.
2. Implement `parse_npm_lockfile()` supporting lockfile v2/v3 (`packages`
   key) with a fallback path for legacy v1 (`dependencies`, recursive).
3. Implement `parse_requirements_txt()` for pinned `==` lines; skip and
   warn (not silently drop) unpinned/VCS lines.
4. Implement `parse_lockfile()` as the single dispatch entry point.
5. Implement `_dedupe()` by `(ecosystem, name, version)`.
6. **Tests before moving on:** fixture lockfiles for npm v1/v2/v3 with
   nested transitive deps, and a `requirements.txt` mixing pinned,
   unpinned, and comment lines. Assert exact expected `Dependency` lists.

**Exit criteria:** 100% of Phase 1 tests pass with zero network calls.

## Phase 2 — OSV.dev API Client & Data Mapping
**Goal:** A tested client that performs the batch-then-hydrate pattern
against a *mocked* `requests.Session`, plus documented behavior against
the real API.

1. Implement `batch_query()`: build the `/v1/querybatch` payload, chunk
   at `MAX_BATCH_SIZE`, parse the response into `Dict[str, set[str]]`.
2. Implement `hydrate_vulns()`: fetch `/v1/vulns/{id}` per unique ID.
3. Implement `_request_with_retries()`: shared retry/backoff wrapper used
   by both of the above; must handle `429`, `5xx`, connection errors, and
   timeouts identically.
4. **Tests before moving on:** mock `requests.Session.request` to return
   canned batch and hydrate responses; assert correct chunking, correct
   dedup of vuln IDs before hydration, and correct retry count on
   simulated `500`/`429` responses without making real network calls.
5. Manual/integration verification: one real call against
   `https://api.osv.dev/v1/query` for a known-vulnerable package (e.g.
   `lodash==4.17.15`) to confirm the schema assumptions in `Schema.md`
   still hold — do this outside the unit test suite (mark it
   integration-only / opt-in) so CI doesn't depend on live network.

**Exit criteria:** All client tests pass fully mocked; one documented
manual verification against the live API is recorded (curl transcript or
equivalent) in a comment or fixture file.

## Phase 3 — Core Logic, Filtering, & CLI Framework
**Goal:** Wire parser + client + evaluator into a working `argparse` CLI
with correct exit codes, before any visual polish.

1. Implement `severity.assess()` and `severity.fixed_version()` as pure
   functions (see `Schema.md` §5 for the exact precedence rules).
2. **Tests before moving on:** a record with only a CVSS vector, a record
   with only `database_specific.severity`, a record with both (assert
   CVSS wins), and a record with neither (assert `UNKNOWN`, never raises).
3. Implement `build_arg_parser()` with all V1 flags from `AppFlow.md` §1.
4. Implement `run()` orchestrating parse → query → hydrate → assess →
   threshold check → exit code, with the exact error-handling paths in
   `AppFlow.md` §3 (malformed file → exit 2, API failure → exit 0 or 1
   depending on `--fail-open`, etc).
5. **Tests before moving on:** end-to-end `run()` tests with
   `osv_client.batch_query`/`hydrate_vulns` mocked via
   `unittest.mock.patch`, covering: a passing scan, a failing scan at
   each threshold boundary, an API-failure with and without
   `--fail-open`, and a malformed-file usage error.

**Exit criteria:** `python -m dep_gate.cli --file <fixture> --fail-on
high` produces the correct exit code and JSON report for every scenario
in the test matrix above, with zero real network calls in the test suite.

## Phase 4 — Terminal UI (Rich) & Reporting
**Goal:** Human-legible output without changing any exit-code or JSON
behavior from Phase 3.

1. Add the optional `rich` import with the `_RICH` fallback flag; verify
   the CLI still produces correct (plain-text) output with `rich`
   uninstalled.
2. Implement the findings table per `Design.md` §3.2 (fixed column order,
   severity-descending sort, non-blank Fix column).
3. Implement the summary line per `Design.md` §3.3 (grep-able
   `SCAN FAILED`/`SCAN PASSED` prefix).
4. Implement the diff-mode preamble line per `Design.md` §3.4.
5. **Tests before moving on:** capture stdout for both the Rich and
   non-Rich code paths and assert the `SCAN FAILED`/`SCAN PASSED` literal
   appears, and that severity color styling doesn't leak raw ANSI codes
   into the `--json` output (JSON must contain plain strings only).

**Exit criteria:** Visual output matches `Design.md`; JSON output is
byte-identical whether or not `rich` is installed.

## Phase 5 — CI/CD Wrappers & Delta Scanning
**Goal:** Make the tool usable as a real PR gate, not just a local CLI.

1. Implement `diff.py`: `get_base_dependencies()` via `git show`
   (subprocess, list-form args only — see `Rules.md` on `subprocess`
   safety), returning `[]` for a file absent at the base ref rather than
   raising.
2. Implement `diff_dependencies()`: set-diff current vs. base by
   `(ecosystem, name, version)`.
3. Wire `--diff-only`/`--base-ref` into `cli.run()` per `AppFlow.md` §2.
4. **Tests before moving on:** a real (temp-dir) git repo fixture with a
   base commit and a feature-branch commit that bumps one dependency and
   adds another; assert the diff returns exactly the changed/new entries
   and excludes the untouched one. Also test the "file didn't exist at
   base ref" path explicitly.
5. Write `.github/workflows/security-scan.yml` with `fetch-depth: 0` and
   both npm/PyPI scan steps using `--diff-only --base-ref
   origin/${{ github.base_ref }}`.
6. **(V2, separate future phase, do not start until V1 phases are done
   and stable):** GitHub PR commenting per `Design.md` §4 — idempotent
   comment updates via the GitHub API, gated behind a new `--pr-comment`
   flag that is off by default.

**Exit criteria:** A real test PR against a real repo with the workflow
installed correctly blocks merge on an intentionally-reintroduced known
vulnerable pin, and does *not* flag an untouched pre-existing vulnerable
pin when `--diff-only` is set.
