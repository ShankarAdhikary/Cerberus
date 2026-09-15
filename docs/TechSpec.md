# TechSpec.md — Technical Specification

## 1. Architecture Overview

The tool is a single Python package, `dep_gate`, structured as independent
modules with a strict one-directional dependency flow (no circular
imports, no module reaching back into `cli.py`):

```
dep_gate/
├── __init__.py       # package version only
├── lockfile.py        # Parser module    - file bytes -> List[Dependency]
├── diff.py            # Diff module       - git ref + file -> List[Dependency] (filtered)
├── osv_client.py       # API client module - List[Dependency] -> vuln IDs -> hydrated records
├── severity.py         # Evaluator module - hydrated record -> Severity(level, score, source)
├── sbom.py             # SBOM module       - List[Dependency] -> CycloneDX dict (no network, no findings)
├── suppress.py          # Suppression module - .dep-gate-ignore.yml -> List[Suppression] (no network)
├── sarif.py             # SARIF module      - findings[] -> SARIF 2.1.0 dict (no network)
├── cache.py             # Cache module      - flat JSON, TTL-based, hydrated-record cache (no network)
├── github_client.py     # GitHub API client - opt-in PR comment (2nd, only other, network boundary)
└── cli.py              # Entry point       - argparse, orchestration, Reporter (Rich/plain)
```

Each module is independently unit-testable with no network access
required except `osv_client.py` and `github_client.py`, the only two
modules that import `requests` and the tool's only two network
boundaries — `osv_client.py` always runs, `github_client.py` only when
the user explicitly passes `--pr-comment`. This matters for testing
(mock at each client module's function boundary, never inside it) and for
security review (network egress is auditable to one file).

## 2. Module Responsibilities

### 2.1 Parser module (`lockfile.py`)
- `parse_npm_lockfile(filepath) -> List[Dependency]`: handles npm
  lockfile v2/v3 (`packages` key, keyed by `node_modules/...` path) and
  falls back to legacy v1 (`dependencies` key, recursively nested).
- `parse_requirements_txt(filepath) -> List[Dependency]`: regex-matches
  pinned `name==version` lines; unpinned/VCS/URL lines are skipped with a
  printed warning, never silently dropped without notice.
- `parse_go_sum(filepath) -> List[Dependency]`: parses `module
  version[/go.mod] hash` lines from a `go.sum` file into
  `ecosystem="Go"` dependencies. A module normally appears twice (a
  content-hash row and a `/go.mod`-hash row); both collapse to the same
  `(ecosystem, name, version)` key via `_dedupe()`. A module with only a
  `/go.mod` row (no content hash needed for compilation) is still kept —
  it's part of the module graph.
- `parse_cargo_lock(filepath) -> List[Dependency]`: parses a Rust
  `Cargo.lock` (TOML, via the stdlib `tomllib`) into `ecosystem="crates.io"`
  dependencies. Only `[[package]]` entries whose `source` starts with
  `registry+` are included; path dependencies (workspace members — no
  `source` key at all) and git dependencies (`source` starts with `git+`)
  are skipped, since neither is published to crates.io or has an
  OSV-resolvable version.
- `parse_lockfile(filepath) -> List[Dependency]`: dispatches on filename
  (`package-lock.json`, `go.sum`, `Cargo.lock`, or `*.txt`). This is the
  only public entry point the rest of the codebase should call.
- All parsers deduplicate on `(ecosystem, name, version)` before
  returning, since the same pinned version can appear multiple times in
  a dependency tree.

### 2.2 API client module (`osv_client.py`)
- Implements the **batch-then-hydrate** pattern (see §3 below) as two
  public functions: `batch_query()` and `hydrate_vulns()`.
- Owns all retry/backoff/timeout policy. No other module should import
  `requests` directly.
- Accepts an optional `requests.Session` parameter on every public
  function so callers (and tests) can inject a pre-configured or mocked
  session without monkeypatching internals.

### 2.3 Evaluator module (`severity.py`)
- `assess(vuln_record: dict) -> Severity`: pure function, no I/O. Given a
  hydrated OSV record, returns the worst-case severity across all
  `severity[]` entries and `affected[].database_specific.severity`
  fallbacks.
- `fixed_version(vuln_record, ecosystem, package_name, installed_version=None)
  -> Optional[str]`: pure function that extracts the lowest *applicable*
  fixed version for a specific package from the record's
  `affected[].ranges[].events[]`. A record can cover multiple disjoint
  vulnerable ranges for the same package (confirmed live: GHSA-43w2-9j62-hq99
  / smallvec@crates.io splits a 0.x branch fixed in `0.6.14` and a 1.x
  branch fixed in `1.6.1` across two `affected` blocks; its RUSTSEC-2021-0003
  alias expresses the identical two branches as one `ranges` entry with
  two `introduced`/`fixed` event pairs back to back), so `installed_version`
  is used to select only the range that actually contains it — otherwise
  an app on 1.6.0 could be told to "upgrade to" 0.6.14, a downgrade. See
  `Schema.md` §5.3.
- Being pure and I/O-free, this module must have the highest unit-test
  coverage of the codebase (see `Rules.md` — parsers and evaluators are
  tested before implementation, not after).

### 2.4 Diff module (`diff.py`)
- `get_base_dependencies(filepath, base_ref) -> List[Dependency]`: reads
  file content at a git ref via `subprocess.run(["git", "show", ...])`
  without touching the working tree; returns `[]` (not an error) only when
  `git`'s stderr indicates the path is genuinely absent at an otherwise
  *resolvable* ref (`"does not exist in"` / `"exists on disk, but not
  in"` — a brand-new lockfile). Any other non-zero exit — an unresolvable
  `base_ref` (typo, or a shallow clone missing history), or not being
  inside a git repository at all — raises `GitDiffError` instead, per §4
  below. Treating every non-zero exit as "file absent" was a discovered
  bug (silently full-scanning instead of exiting 2) fixed alongside the
  formal test suite; see `tests/test_diff.py`'s regression tests.
- `diff_dependencies(filepath, base_ref) -> List[Dependency]`: set-diffs
  current vs. base dependencies by `(ecosystem, name, version)` tuple. A
  version change is treated as "new" (both old and new version keys will
  differ), which is intentional — see PRD §4 rationale.
- Raises `GitDiffError` (not a bare `RuntimeError`) if `git` itself is
  missing, so the CLI layer can produce an actionable message rather than
  a raw traceback.

### 2.5 SBOM module (`sbom.py`)
- `build_sbom(dependencies: List[Dependency]) -> dict`: pure function,
  no I/O. Builds a minimal CycloneDX 1.5 document (`bomFormat`,
  `specVersion`, `components[]`) directly from the flat `Dependency` list
  that `lockfile.py`/`diff.py` already produce — independent of
  `severity.py`'s findings, since an SBOM is an inventory ("what's in
  the build"), not a risk report ("what's vulnerable"). No dependency
  graph/relationships are emitted, since the parsers don't track edges
  between packages and fabricating one would misrepresent the data.
- Each component gets a `purl` (package URL) built from a small
  ecosystem → purl-type map, since OSV's ecosystem strings don't always
  match purl's `type` component (`PyPI`→`pypi`, `Go`→`golang`,
  `crates.io`→`cargo`; `npm` matches as-is).
- `cli.run()` writes the SBOM (when `--sbom PATH` is given) from whichever
  dependency list was actually scanned — the full lockfile, or only the
  changed subset under `--diff-only` — right after that list is resolved
  and before the OSV network calls, so it's still written even if OSV.dev
  is unreachable, and even for a zero-dependency lockfile (`components: []`,
  not an error). It is *not* written on a usage error (exit 2), since no
  dependency list was ever resolved in that case.

### 2.6 Suppression module (`suppress.py`)
- `load_suppressions(filepath) -> List[Suppression]`: parses
  `.dep-gate-ignore.yml`'s deliberately narrow YAML subset (a top-level
  list of flat mappings, plain scalar values, `#` comments) with a small
  hand-rolled parser rather than a `PyYAML` dependency - the fixed shape
  doesn't need a general YAML engine, and this avoids a new third-party
  dependency for one config file. Raises `ValueError`/`FileNotFoundError`
  (never silently drops a bad entry) if `vuln_id`, `expires`, or `reason`
  is missing/blank, or `expires` isn't a valid `YYYY-MM-DD` date.
- `find_active_suppression(vuln_id, package, suppressions, today=None)
  -> Optional[Suppression]`: pure function, no I/O. Matches by `vuln_id`
  and (if the entry specifies one) `package`; an entry past its `expires`
  date never matches, so expiry is enforced by the tool itself, not just
  documented convention.
- `cli.run()` calls this only when `--ignore-file` is given; a matching
  finding is marked `suppressed=True` (with `suppression_reason`) and
  excluded from the `--fail-on` `blocking` computation, but stays in the
  table/JSON output (marked `SEVERITY (suppressed)`) - see `Design.md`'s
  suppression note and `Schema.md` §3.5, per PRD.md's requirement that
  suppressions be auditable, never silent.

### 2.7 SARIF module (`sarif.py`)
- `build_sarif(findings, scanned_file) -> dict`: pure function, no I/O.
  Builds a minimal SARIF 2.1.0 document from `cli.py`'s `findings[]` (the
  same records `--json` writes) - a second output shape for the same
  data, for `github/codeql-action/upload-sarif` to surface findings in
  GitHub's code-scanning UI, not a replacement for `--json`.
- One SARIF "rule" per unique `vuln_id` (deduplicated the same way
  `osv_client.hydrate_vulns()` dedupes fetches), one "result" per
  finding. Severity maps onto SARIF's coarser `level` enum:
  CRITICAL/HIGH → `error`, MODERATE → `warning`, LOW/UNKNOWN → `note`.
- Results are whole-file (`locations[].physicalLocation.artifactLocation.uri`
  = the scanned lockfile path, no line/column region) - findings map to a
  resolved `(package, version)`, not a source position, and `lockfile.py`'s
  parsers don't track positions, so a fabricated region would misrepresent
  the data.
- A suppressed finding (`--ignore-file`) is marked via SARIF's own native
  `result.suppressions` field (`kind: "external"`, with the suppression's
  `reason` as `justification`) rather than omitted, matching PRD.md's
  auditability requirement — GitHub's code-scanning UI understands this
  field and displays such results as dismissed/suppressed, not absent.

### 2.8 Cache module (`cache.py`)
- `load_cache(cache_path) -> Dict[str, dict]` / `save_cache(cache_path,
  cache)`: a flat JSON file `{vuln_id: {"record": {...}, "cached_at":
  <unix ts>}}`. A missing or corrupt cache file is treated as an empty
  cache (never raises) - a broken cache must never take down the scan.
- `get_fresh(cache, vuln_id, now) -> Optional[dict]` / `put(cache,
  vuln_id, record, now)`: pure functions, no I/O.
- **TTL, not the `modified` timestamp**: `osv_client.batch_query()`'s
  response does carry a per-result `modified` field (Schema.md §5.1)
  that a cache could in principle use for exact staleness detection -
  but that would require changing `batch_query()`'s documented, tested
  return shape (`Dict[str, set[str]]`) into something else. A
  `CACHE_TTL_SECONDS` bound (6 hours) delivers the same practical
  benefit — skip re-fetching a record fetched very recently — without
  touching that existing contract, and keeps the staleness window small
  and explicit rather than open-ended. (Supersedes Schema.md §5.1's
  earlier note speculating a `modified`-based cache.)
- `cli.run()` only touches this module when `--cache-file PATH` is
  given: it partitions the batch-query's vuln IDs into cache hits
  (`get_fresh`) and misses, calls `hydrate_vulns()` only for the misses
  (skipping the call entirely if there are none), then `put()`s and
  saves back only the freshly-fetched records — an existing fresh cache
  entry's `cached_at` is left untouched, so its TTL window counts from
  when it was actually last fetched, not from every scan. Without
  `--cache-file`, behavior is unchanged from before this feature existed
  (always fetches every vuln ID fresh).
- For persistence *across* CI runs (the actual point of this cache),
  the workflow must restore/save the cache file itself. `security-scan.yml`
  uses split `actions/cache/restore@v4` + `actions/cache/save@v4` steps
  (not the combined `actions/cache@v4` action) specifically so the save
  step can carry `if: always()` — this gate's job legitimately fails on
  real findings, and a PR sitting on an unfixed vulnerability across
  repeated pushes is exactly the case that most needs a persisted cache.
  The combined action's own `save-always` input looks like the obvious
  fix but is deprecated and, confirmed live across three real runs in
  this project's own demo PR, does not actually save anything — "Cache
  not found" persisted even with `save-always: true` set. The
  restore/save split is what GitHub's own deprecation notice points at
  as the replacement, and it's what was verified live to actually work.

### 2.9 GitHub API client module (`github_client.py`)
- This is the tool's SECOND (and, per PRD.md's zero-telemetry NFR, only
  other) network egress point, after `osv_client.py`. `cli.py` never
  imports or calls it unless `--pr-comment` is set.
- **Auth model**: the workflow's own `GITHUB_TOKEN`, read from that
  environment variable inside the tool (never accepted as a CLI
  argument, to avoid it appearing in `ps`/process listings or CI logs),
  with job-scoped `permissions: pull-requests: write` in the workflow
  YAML — not a GitHub App. See Tracker.md's "Resolved decisions": this
  is a single-repo PR-gate tool, and a GitHub App would add
  registration/installation/secret-management infrastructure PRD.md's
  own NFRs reject.
- `render_pr_comment(blocking, scanned_count, fail_on, diff_mode,
  base_ref) -> str`: pure function, no I/O. Renders the exact Markdown
  structure in `Design.md` §4. Shows only *blocking* findings above the
  fold (not every LOW/UNKNOWN finding, matching the table's own noise
  rule) and never includes a raw CVSS vector string.
- `find_existing_comment_id()` / `upsert_comment()`: find the bot's own
  prior comment via a hidden `COMMENT_MARKER` and PATCH it instead of
  posting a new comment on every push — `Design.md` §4's idempotency
  rule — accepting an optional `requests.Session` for testing, same
  pattern as `osv_client.py`.
- `_request_with_retries()`: same retry/backoff shape as
  `osv_client.py`'s function of the same name (`MAX_RETRIES = 3`,
  `BACKOFF_BASE = 1.0`s, retries on `429`/`5xx`/connection errors/timeouts,
  raises `RuntimeError` on exhaustion), additionally honoring GitHub's
  `Retry-After` response header (sent on secondary rate limits) in
  preference to the fixed backoff schedule when present. Without this, a
  transient GitHub API hiccup surfaced immediately as a (non-blocking,
  but noisy) "failed to post PR comment" warning — added after review
  feedback flagged the missing retry policy as a real gap for anyone
  running this across many repos/PRs on a low-quota token.
- A comment-posting failure (network error, bad token, rate limit) is
  caught in `cli.run()` and printed as a warning; it never changes the
  scan's own exit code — per `AppFlow.md` §4, this is additive output,
  not a replacement for the terminal/JSON/SARIF report.
- **Verification note**: `render_pr_comment()`, `find_existing_comment_id()`,
  and `upsert_comment()` are unit-tested against a mocked
  `requests.Session` (same pattern as `osv_client.py`'s tests), and have
  since also been run for real against `ShankarAdhikary/Cerberus#1` —
  idempotent create and update both confirmed live (see Tracker.md for
  the exact comment IDs/timestamps observed).

### 2.10 Entry point / Reporter (`cli.py`)
- Owns `argparse` definition, orchestration order, exit-code decisions,
  and the terminal/JSON reporting layer. See `Design.md` for the exact
  Rich table layout and `AppFlow.md` for the full control flow.
- Rich is an optional import — the CLI must run correctly (with plain
  `print()` output) even in a minimal environment where `rich` isn't
  installed, since CI runners may cache a stale `requirements.txt`.
- **Multi-file `--file` support**: `--file` is repeatable
  (`action="append"`, `dest="files"`) rather than `nargs="+"` — chosen
  because repeated flags read unambiguously next to every other flag in
  a long invocation (no risk of a following bare value being swallowed
  as another file, which `nargs="+"` is prone to without a `--`
  separator), and it matches how the CI workflow already lists one
  concept per line. `run()` resolves every file's dependency list up
  front in a loop, **failing fast on the first usage error** — if file 2
  of 3 fails to parse, `run()` returns `2` immediately without ever
  calling `osv_client`, rather than scanning file 1, reporting on it,
  and only then discovering file 2 is broken (AppFlow.md §2's exit-code
  contract requires this explicitly).
  - **Byte-compatibility with a single `--file`** (Rules.md: docs stay
    authoritative for behavior that must not regress) is achieved by
    gating every multi-file-only addition behind `multi_file = len(args.files) > 1`:
    a single-file run never adds a `source_file` key to any finding, never
    adds a "File" column to the table, and calls `sarif.build_sarif(findings,
    args.files[0])` exactly as before (passing the one file positionally, the
    same as the old single-argument call) — so its JSON/SARIF/SBOM output is
    identical to pre-multi-file output down to the byte. This is enforced by
    `tests/test_backward_compat.py`, which diffs live output against a golden
    fixture captured from the actual pre-refactor code, not just fresh
    assertions written after the fact.
  - **Multi-file** run: every dependency gets tagged `dep["source_file"] =
    file_path` right after that file's own parse/diff step (`cli.py` does
    this tagging itself - `lockfile.py`/`diff.py` are untouched and know
    nothing about multi-file scans). Findings inherit `source_file` from
    their dependency. `sbom.build_sbom()` needs no change at all - it never
    reads `source_file` and a CycloneDX inventory has no natural per-file
    concept to add one for (not requested, not added). `sarif.build_sarif()`
    is called with `scanned_file=None`, so every result falls back to its own
    finding's `source_file` instead of one global filename (see `sarif.py`'s
    docstring for the exact fallback rule).
  - **Exit-code aggregation** (AppFlow.md §2) falls out of the existing
    single-pass logic without any extra aggregation code: `blocking` is
    already computed from the *combined* findings list across all files, so
    "exit 1 if ANY file has a blocking finding" is just what iterating the
    union already does; "exit 0 only if every file is clean" is the same
    computation in the other direction. The only genuinely new control flow
    is the fail-fast parse loop described above.
  - **`--pr-comment`** now groups blocking findings under a `### \`file\``
    subheading per source file when `len(scanned) > 1` (see
    `github_client.render_pr_comment()`'s docstring) - with exactly one
    file, it renders the flat table it always has, unchanged.

## 3. OSV.dev Integration Details

### 3.1 Why two calls, not one
`POST /v1/querybatch` is intentionally minimal: it returns only matching
vulnerability **IDs** and a `modified` timestamp per query — never
severity, description, or fix data. To get the full record you must
separately call `GET /v1/vulns/{id}` (or the single-item `POST /v1/query`,
which does return a full record) per **unique** ID. Treating querybatch's
response as if it contained severity data is the most common integration
bug against this API and must be explicitly avoided.

### 3.2 Batch request payload
```json
POST https://api.osv.dev/v1/querybatch
Content-Type: application/json

{
  "queries": [
    {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.15"},
    {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.25.0"}
  ]
}
```
Response (order-preserving, one result entry per input query):
```json
{
  "results": [
    {"vulns": [{"id": "GHSA-jf85-cpcp-j695", "modified": "2020-09-02T22:36:00Z"}]},
    {"vulns": []}
  ]
}
```

### 3.3 Hydration request
```
GET https://api.osv.dev/v1/vulns/GHSA-jf85-cpcp-j695
```
Returns the full OSV schema record (`severity[]`, `affected[]`, `summary`,
`references[]`, etc.) — see `Schema.md` for the exact field mapping into
internal dataclasses.

### 3.4 Batching, retries, and limits
- Chunk queries at `MAX_BATCH_SIZE = 1000` per request (a defensive
  client-side cap; OSV has no officially documented hard limit but very
  large single requests risk the API's 32 MiB response ceiling).
- `ecosystem` strings are case-sensitive and must match OSV's canonical
  values exactly: `npm`, `PyPI`, `Go`, `crates.io`, `Maven`, `RubyGems`,
  `Packagist`. A mismatched case silently returns zero matches — this is
  not surfaced as an API error, so ecosystem strings must be
  unit-tested, not just assumed correct.
- Retry policy: on `429` or any `5xx`, retry up to `MAX_RETRIES = 4`
  times with exponential backoff (`BACKOFF_BASE * 2**attempt` seconds).
  On exhaustion, raise `RuntimeError` — the CLI layer decides whether
  that becomes exit code `1` (fail-closed, default) or `0`
  (`--fail-open`).
- Every request uses a shared `requests.Session` with a
  `REQUEST_TIMEOUT = 15` second timeout; no request is fired without a
  timeout, ever.

## 4. CI/CD Execution Context

- The tool assumes it runs as a **step** inside a job, not as the whole
  job — it reads a lockfile from the working directory and writes an
  optional JSON report file; it does not manage checkout, dependency
  installation, or artifact upload itself (those are the CI YAML's job).
- **Exit codes are the sole signal to CI.** `sys.exit(0)` on pass,
  `sys.exit(1)` on a policy violation, `sys.exit(2)` on a usage/tool
  error (bad path, unreadable git ref). CI YAML must not swallow the
  exit code (no `|| true` on the scan step) or the gate becomes
  decorative.
- `--diff-only` requires the checkout step to have fetched the base
  branch's history (`fetch-depth: 0` in `actions/checkout@v4`); a
  shallow clone will cause `git show <base_ref>:<file>` to fail with a
  non-zero exit that `diff.py` must surface as `GitDiffError`, not a
  silent empty diff.
- `security-scan.yml` runs `--diff-only` only for the `pull_request`
  trigger (`github.event_name == 'pull_request'`, via a GitHub Actions
  expression in the `run:` block, since `github.base_ref` doesn't exist
  on a `push` event); the `push: branches: [main]` trigger runs a full,
  non-diff scan instead. This full scan on `main` isn't optional
  polish — GitHub's code-scanning alerts only ever report a PR's
  findings as "new" relative to the last analysis on the default
  branch, so without at least one scan having landed on `main`, a PR's
  SARIF upload succeeds but never surfaces as a visible alert. Confirmed
  live: a real PR's code-scanning check reported "No new alerts" despite
  its own SARIF containing 8 real findings, until this trigger existed.

## 5. Packaging & Distribution

- **PyPI package name: `dep-vuln-gate`, not `dep-gate`.** `dep-gate` was
  the original choice and passed the obvious availability check
  (`GET https://pypi.org/pypi/dep-gate/json` → `404`, confirmed before
  committing to it) — but that check only proves the *exact* name is
  unclaimed, not that PyPI's upload-time validator will accept it. The
  real upload was rejected: `400 The name 'dep-gate' is too similar to
  an existing project` — PyPI normalizes away hyphens/case when checking
  similarity, and an unrelated existing package, `depgate` (a dependency-
  confusion/supply-chain-risk detector, thematically adjacent but not
  the same tool), already claims that normalized form. There is no
  practical way to discover this in advance short of attempting the
  upload — the JSON API has no "similar names" endpoint. `dep-vuln-gate`
  (matching this repo's own directory name) was checked and clear, and
  the upload succeeded under it. The **console command** stays `dep-gate`
  (`[project.scripts]` isn't required to match `[project.name]`) - only
  the `pip install <name>` target changed, not what a user actually
  types to run the tool.
- **Build backend: hatchling**, not setuptools. No concrete reason to
  prefer setuptools existed (no C extensions, no complex package-data
  rules), and hatchling's `[tool.hatch.version]` reads `__version__`
  directly out of `dep_gate/__init__.py` as a single source of truth —
  the version is declared exactly once in the whole repo
  (`dynamic = ["version"]` in `pyproject.toml`'s `[project]` table),
  rather than duplicated into `pyproject.toml` where it could silently
  drift from what `dep_gate.__version__` actually reports at runtime.
- **`requirements.txt` vs. `pyproject.toml`'s `[project.dependencies]`**:
  `pyproject.toml` is authoritative. `requirements.txt` is kept as an
  exact hand-maintained mirror (a comment at its top says so) rather than
  deleted outright, since it's still the install path for anyone running
  `python -m dep_gate.cli` directly without installing the package (the
  original, still-supported invocation form — see the module docstring)
  and for `requirements-dev.txt`'s `-r requirements.txt` chain. There is
  no automated check preventing the two from drifting; keeping them in
  sync is a manual discipline enforced by this doc, not tooling — both
  files are short and rarely touched, so the risk is low, but a future
  agent changing one must update the other.
- **Console script**: `dep_gate.cli:run` is used directly as the
  `[project.scripts]` target — `run()` already returns an `int` exit
  code and needs no `main()` wrapper, because the console-script shim
  `pip`/`hatchling` generate calls `sys.exit(<entry point callable>())`
  itself. Confirmed live, not assumed: installing the package and running
  `dep-gate --file /nonexistent/package-lock.json` exits `2` (a real
  usage error), proving the entry point's return value genuinely becomes
  the process exit code, not just that `--help` happens to exit `0` via
  argparse's own `SystemExit`.
- **What ships**: `[tool.hatch.build.targets.wheel].packages = ["dep_gate"]`
  and `[tool.hatch.build.targets.sdist].include` are both scoped
  explicitly to `dep_gate/`, `README.md`, and `LICENSE` — `docs/`,
  `tests/`, and `.github/` are deliberately excluded from both the wheel
  and the sdist (confirmed by inspecting `unzip -l`/`tar tzf` output on a
  real build - see Tracker.md for the exact file lists observed). A
  package artifact ships the importable code and the metadata a PyPI
  listing needs, not the whole repository.
- **Distribution paths, both verified end-to-end in clean venvs**:
  `pip install dep-vuln-gate` (real PyPI — https://pypi.org/project/dep-vuln-gate/)
  and `pip install git+https://github.com/<owner>/<repo>.git@<tag>` (zero
  PyPI involvement, only a git tag). Both were confirmed with a real
  install, `dep-gate --help`, and a real live OSV.dev scan against a
  known-vulnerable pin producing the correct findings and exit code — see
  Tracker.md for the exact commands and output.
