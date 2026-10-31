# Cerberus: Dependency Vulnerability Gate

Created by [Shankar Adhikary](https://github.com/ShankarAdhikary).

A minimal Software Composition Analysis (SCA) CLI that scans `package-lock.json`
or `requirements.txt` against the [OSV.dev](https://osv.dev) vulnerability
database and fails CI when findings meet a severity threshold.

## How it works

1. **Parse** the lockfile into a flat list of `{name, version, ecosystem}`.
2. **Batch query** `POST /v1/querybatch` — cheap, returns only vulnerability
   IDs per package, not full details.
3. **Hydrate** each *unique* vulnerability ID via `GET /v1/vulns/{id}` to get
   the full record (severity, description, fixed version), caching so the
   same CVE isn't fetched twice even if it affects many packages.
4. **Score** each finding: parse the CVSS vector if present, fall back to
   the advisory's plain-text `database_specific.severity` rating, or mark
   it `UNKNOWN` if neither exists.
5. **Gate**: exit `1` if any finding is at or above `--fail-on` (default
   `high`), else exit `0`.

## Install

```bash
pip install cerberus-sca
```

From [PyPI](https://pypi.org/project/cerberus-sca/) — verified end-to-end
in a clean venv (install, `--help`, a real live scan against OSV.dev).
Note the PyPI/`pip install` name is `cerberus-sca`, not `cerberus` or
`dep-gate` — `dep-gate` was too similar to an existing, unrelated PyPI
package for PyPI's own upload validator to accept, and the project's own
name, `cerberus`, is already taken by a different, unrelated PyPI package
(a schema/data-validation library, unrelated to this tool). The
**console command** is `dep-gate` (short, what you actually type)
regardless of which name you `pip install`.

Also installable from a tagged release without PyPI at all (equally
verified):
```bash
pip install git+https://github.com/ShankarAdhikary/Cerberus.git@v1.0.0
```

Alternatively, without installing the package at all:
```bash
git clone https://github.com/ShankarAdhikary/Cerberus.git
cd Cerberus
pip install -r requirements.txt
python -m dep_gate.cli --file package-lock.json --fail-on high
```

**In another repo's own CI**, pin to a released version rather than a
moving target:
```yaml
- run: pip install cerberus-sca==1.0.0
- run: dep-gate --file package-lock.json --fail-on high
```

## Usage

```bash
dep-gate --file package-lock.json --fail-on high
dep-gate --file requirements.txt --fail-on critical --json report.json

# Scan every supported lockfile inside a local folder or ZIP archive.
dep-gate --project ./my-project --fail-on high
dep-gate --project ./my-project.zip --fail-on high --json report.json

# --file is repeatable: scan multiple lockfiles in one invocation, with
# one combined JSON/SARIF/SBOM/PR-comment output instead of one per file.
dep-gate --file package-lock.json --file requirements.txt --fail-on high
```

(`python -m dep_gate.cli` works identically to `dep-gate` — the console
script is `dep_gate.cli:run` with no wrapper, so both invoke the exact
same code path. Every example below uses the module form only because it
also works without installing the package; swap in `dep-gate` freely.)

Flags:
- `--file PATH` — **repeatable**. Path to a lockfile
  (`package-lock.json`, `requirements.txt`, `go.sum`, `Cargo.lock`,
  `pom.xml`, `Gemfile.lock`, `composer.lock`).
  Repeat it to scan several in one run; a single `--file` behaves exactly
  as it always has. If omitted when run in an interactive terminal (e.g.
  just typing `dep-gate`), you're prompted for a path instead — this is
  purely a convenience for manual runs; a scripted/CI invocation with no
  terminal to prompt on (and no `--file`) still exits `2` immediately
  rather than hanging on input.
- `--project PATH` — scan a local project directory or `.zip` archive.
  Supported lockfiles are discovered recursively while generated directories
  such as `.git`, `.venv`, `venv`, `node_modules`, and `__pycache__` are
  ignored. Other nested directories, including test fixtures, are scanned
  intentionally so the command inventories the complete project.
  It cannot be combined with `--file`. The project ZIP is extracted to a
  temporary directory and removed after lockfile parsing.
- `--fail-on {low,moderate,high,critical}` — minimum severity that blocks the build.
- `--json PATH` — also write a machine-readable report.
- `--fail-open` — exit `0` instead of `1` if OSV.dev is unreachable (off by
  default; a broken security gate should fail loudly, not silently pass).
- `--diff-only --base-ref REF` — only scan dependencies that are new or
  version-changed relative to `REF` (see "Delta scanning" below).
- `--verbose` — add a "Source" column/JSON field showing how each
  severity was derived (e.g. `CVSS_V3 vector` vs.
  `database_specific.severity`). Off by default; purely additive.
- `--sbom PATH` — write a CycloneDX JSON Software Bill of Materials
  listing every dependency scanned (respects `--diff-only`). Independent
  of findings — written even on a clean scan or an OSV.dev outage. For a
  complete build inventory, run it *without* `--diff-only` — the PR-gate
  workflow below only ever scans the changed subset, so a `--sbom` there
  would be a partial bill of materials, not a full one.
- `--ignore-file PATH` — suppress accepted-risk findings via a
  `.dep-gate-ignore.yml` file (see below). A suppressed finding stays
  visible in the table/JSON (marked, never hidden) and just doesn't
  count toward `--fail-on`.
- `--sarif PATH` — also write a SARIF 2.1.0 report for GitHub
  code-scanning upload (`github/codeql-action/upload-sarif`). Same
  findings as `--json`, different shape.
- `--spdx PATH` — write an SPDX 2.3 JSON Software Bill of Materials.
- `--cache-file PATH` — reuse a local JSON cache of hydrated OSV records
  across runs, skipping re-fetches for a vuln ID already fetched within
  the last 6 hours. Off by default. Persist the file across CI runs
  (e.g. `actions/cache`) to get the actual benefit.
- `--pr-comment` — post/update an idempotent PR comment summarizing
  blocking findings, via the GitHub API. Off by default — this is the
  tool's *only other* network egress point besides `api.osv.dev`.
  Requires `--github-repo OWNER/REPO`, `--github-pr-number N`, and a
  `GITHUB_TOKEN` environment variable (the workflow's own token — never
  pass it as a CLI argument). A comment-posting failure prints a warning
  but never changes the exit code.

Project and ZIP inputs are local-only. The scanner does not download arbitrary
URLs or execute project code. GitHub repository import is not part of the
current release.

```yaml
# in a pull_request-triggered job, with:
#   permissions:
#     pull-requests: write
- run: >
    python -m dep_gate.cli --file package-lock.json --file requirements.txt
    --fail-on high
    --pr-comment
    --github-repo ${{ github.repository }}
    --github-pr-number ${{ github.event.pull_request.number }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

This is exactly what `.github/workflows/security-scan.yml` does: one combined
invocation across every lockfile present, so `--pr-comment` posts a
single comment covering all of them (grouped by file)
instead of one ecosystem's `--pr-comment` call finding-and-overwriting
another's. (An earlier version of this project ran one `dep_gate.cli`
invocation per ecosystem, which made `--pr-comment` impossible to wire in
safely — each invocation would've silently dropped every other
ecosystem's findings from the comment. Multi-file `--file` support fixed
that at the root, rather than working around it.)

## Suppressing accepted-risk findings

```yaml
# .dep-gate-ignore.yml
- vuln_id: GHSA-jf85-cpcp-j695
  package: lodash          # optional - omit to suppress this ID for any package
  expires: 2026-12-31       # required
  reason: "Accepted risk - vendor patch pending, tracked in JIRA-1234"
```

`vuln_id`, `expires` (`YYYY-MM-DD`), and a non-blank `reason` are all
required per entry — a malformed file exits `2` rather than silently
ignoring the bad entry. Once `expires` passes, the entry stops
suppressing automatically and that finding blocks the build again.

```bash
python -m dep_gate.cli --file package-lock.json --ignore-file .dep-gate-ignore.yml
```

## Delta scanning

By default the tool re-scans every dependency in the lockfile on every run.
With `--diff-only`, it instead reads the lockfile's content at `--base-ref`
via `git show` (no checkout needed), parses both versions, and only reports
on dependencies that are **new** or have a **different pinned version** —
a version bump counts as changed even if the old version had no known
vulnerabilities, since the new one might.

This mirrors how Dependabot avoids re-flagging pre-existing vulnerable
dependencies on every PR: a gate that only complains about risk *you just
introduced* is far less likely to get muted or bypassed by a frustrated team.

```bash
python -m dep_gate.cli --file requirements.txt --diff-only --base-ref origin/main
```

Requires running inside a git repo with the base ref actually fetched — in
GitHub Actions this means `actions/checkout@v4` with `fetch-depth: 0`
(shallow clones won't have the base branch's history available). If the
lockfile didn't exist at the base ref at all (e.g. it's brand new), every
dependency in it is treated as new — not an error.

## Supported lockfiles

- `package-lock.json` (npm lockfile v1, v2, and v3 — including transitive deps)
- `requirements.txt` (only pinned `==` lines have a resolvable version;
  unpinned/VCS lines are skipped with a warning)
- `go.sum` (Go modules — the `/go.mod`-hash and content-hash rows for the
  same module collapse into one dependency)
- `Cargo.lock` (Rust — only registry (crates.io) packages are checked;
  path/workspace and git dependencies are skipped, since they aren't
  published to crates.io and have no OSV-resolvable version)
- `pom.xml` (Maven direct dependencies with explicit versions)
- `Gemfile.lock` (RubyGems resolved specs)
- `composer.lock` (Packagist production and development packages)

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
ruff format --check .
ruff check .
```

The suite is fully network-free (the OSV.dev boundary is mocked in
`tests/test_osv_client.py` and `tests/test_cli.py`); `tests/test_diff.py`
spins up real temporary git repositories rather than mocking `git`.
The same checks run in `.github/workflows/quality.yml`, which also validates
package compilation and distribution metadata.

## CI integration

See `.github/workflows/security-scan.yml`. Two triggers:
- **`pull_request`** — diff-only scan of whatever lockfile(s) the PR
  touches; uploads the JSON report as a build artifact and the SARIF
  report to code scanning.
- **`push` to `main`** — full (non-diff) scan on every merge. This isn't
  just belt-and-suspenders: GitHub's code-scanning alerts only report a
  PR's findings as "new" relative to the last analysis on the default
  branch, so without this trigger a PR's SARIF upload silently never
  shows up as a visible alert, even though it succeeds.
- **Scheduled scans** — the security scan runs daily, and quality checks run
  weekly, so OSV/API or tooling drift is detected even when no lockfile
  changes.

## Release status

The latest published package/tag is `1.0.0`. The current source tree carries
the next development version in `dep_gate/__init__.py`; releases are built
and published by `.github/workflows/release.yml` when a `v*` tag is pushed.
The workflow uses PyPI trusted publishing, so no long-lived PyPI token is
stored in GitHub secrets.

## Known limitations / good next steps

- Maven, RubyGems, and Packagist support is intentionally limited to
  lockfile entries with concrete versions. Maven properties and unresolved
  dependency-management versions are skipped.
- SPDX and CycloneDX JSON SBOM formats are supported. Neither format
  fabricates dependency relationships because the parsers expose a flat
  resolved inventory.

## License

[MIT](LICENSE)
