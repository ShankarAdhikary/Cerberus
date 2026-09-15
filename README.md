# Dependency Vulnerability Gate

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

## Usage

```bash
pip install -r requirements.txt

python -m dep_gate.cli --file package-lock.json --fail-on high
python -m dep_gate.cli --file requirements.txt --fail-on critical --json report.json
```

Flags:
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

```yaml
# in a pull_request-triggered job, with:
#   permissions:
#     pull-requests: write
- run: >
    python -m dep_gate.cli --file package-lock.json --fail-on high
    --pr-comment
    --github-repo ${{ github.repository }}
    --github-pr-number ${{ github.event.pull_request.number }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Not wired into `security-scan.yml` below**: that workflow scans up to
four lockfiles in separate steps, and each `--pr-comment` invocation
finds-and-overwrites the *same* bot comment via its idempotency marker —
running it after every step would leave the comment reflecting only the
last ecosystem scanned, not the combined picture, which is worse than no
comment at all. Wiring this in for real needs one CLI invocation that
scans every changed lockfile and comments once with the combined
findings — out of scope for the current one-file-per-invocation `cli.py`
design. The snippet above is for a single-lockfile repo/workflow.

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

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The suite is fully network-free (the OSV.dev boundary is mocked in
`tests/test_osv_client.py` and `tests/test_cli.py`); `tests/test_diff.py`
spins up real temporary git repositories rather than mocking `git`.

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

## Known limitations / good next steps

- Four ecosystems supported (`npm`, `PyPI`, `Go`, `crates.io`). OSV also
  covers Maven, RubyGems, Packagist, etc. — the same batch/hydrate client
  works for those, you'd just need lockfile parsers for each.
- SPDX SBOM format not supported (CycloneDX is).
- `--pr-comment` isn't wired into the multi-ecosystem PR-gate workflow
  below — see that section for why.

## License

[MIT](LICENSE)
