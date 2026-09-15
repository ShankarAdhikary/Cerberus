# PRD.md — Dependency Vulnerability Gate

## 1. Problem Statement

Modern applications pull in hundreds of transitive dependencies through
lockfiles (`package-lock.json`, `requirements.txt`, etc.). A single
vulnerable transitive package can compromise an otherwise well-audited
codebase, and most teams only discover this after a breach, a scanner
vendor's quarterly report, or a GitHub Dependabot alert email that gets
lost in noise.

Commercial SCA (Software Composition Analysis) tools like Snyk exist, but
they are often paywalled beyond small usage tiers, add third-party data
egress (your dependency tree leaves your network), and are heavyweight to
integrate into a lean CI pipeline. Teams need a **free, transparent,
self-hosted gate** that runs entirely from public vulnerability data and
fails a build the moment a genuinely risky dependency is introduced —
not a dashboard to check manually.

## 2. Target Audience

| Persona | Need |
|---|---|
| **DevOps Engineer** | Wants a drop-in CI step that doesn't require standing up new infrastructure or paying for a SaaS seat. |
| **AppSec Engineer** | Wants control over the severity policy (what fails the build vs. what's just logged) and an audit trail (JSON report artifact). |
| **Individual OSS maintainer** | Wants a zero-cost gate on pull requests from external contributors, since a compromised transitive dependency is a common supply-chain attack vector on open source projects. |

## 3. Core Use Cases

1. **PR gate**: On every pull request that touches a lockfile, block the
   merge if a newly introduced or version-bumped dependency has a
   HIGH/CRITICAL vulnerability.
2. **Full audit**: On a schedule (e.g. nightly `cron`), scan the entire
   lockfile — not just the diff — to catch vulnerabilities disclosed
   *after* a dependency was already merged in (this is why diff-only mode
   is opt-in, not the default).
3. **Local pre-commit check**: A developer runs the CLI locally before
   opening a PR to get the same signal CI will give them, without
   waiting on a pipeline.
4. **Remediation guidance**: When a vulnerability is found, the developer
   gets the exact upgrade target (`fixed_version`) rather than having to
   go look it up themselves.

## 4. Feature Set

### V1 (must-have, currently implemented)
- Parse `package-lock.json` (npm lockfile v1/v2/v3, including transitive
  deps), `requirements.txt` (pinned `==` entries), `go.sum` (Go modules),
  and `Cargo.lock` (Rust, registry/crates.io packages only).
- Batch-query OSV.dev (`POST /v1/querybatch`) for all extracted
  dependencies.
- Hydrate each unique vulnerability ID (`GET /v1/vulns/{id}`) to obtain
  severity and fix data, deduplicated so a CVE affecting many packages is
  only fetched once.
- Normalize severity from either a CVSS v2/v3 vector or a
  `database_specific.severity` text rating; degrade gracefully to
  `UNKNOWN` when neither is present rather than crashing or false-passing.
- Configurable severity gate (`--fail-on low|moderate|high|critical`).
- Machine-readable JSON report output (`--json PATH`).
- Explicit, opt-in fail-open behavior on API outage (`--fail-open`);
  default behavior is fail-closed (loud failure, not a silent pass).
- GitHub Actions workflow that runs on PRs touching either lockfile and
  uploads the JSON report as a build artifact.
- Delta scanning (`--diff-only --base-ref REF`): only evaluate
  dependencies that are new or version-changed relative to a git ref,
  via `git show <ref>:<path>` (no working-tree checkout required).
- SBOM export (`--sbom PATH`): a CycloneDX JSON inventory of every
  dependency scanned, independent of vulnerability findings.
- Allow-list / suppression file (`--ignore-file PATH`, default filename
  `.dep-gate-ignore.yml`) for accepted-risk exceptions with required
  expiry dates and justification text, so suppressions are auditable
  rather than silent — a suppressed finding stays visible in the
  table/JSON output (marked, not hidden) and simply doesn't count toward
  `--fail-on`; an expired entry stops suppressing automatically.
- SARIF export (`--sarif PATH`): a SARIF 2.1.0 report for GitHub
  code-scanning upload, alongside (not instead of) `--json`.
- Local hydration cache (`--cache-file PATH`): a flat-JSON, TTL-bounded
  cache of hydrated OSV vuln records to avoid re-fetching a vuln ID
  already fetched recently — e.g. across CI jobs in the same repo when
  the cache file is persisted via `actions/cache`.
- Automated, idempotent PR comment summarizing blocking findings
  (`--pr-comment`, opt-in), via the GitHub API using the workflow's own
  `GITHUB_TOKEN` — see the NFR below on this being the tool's second and
  only other network egress point.

### V2 (stretch goals, not yet implemented)
- Additional ecosystems: Java (Maven `pom.xml`/lockfile equivalents),
  Ruby (`Gemfile.lock`).
- SPDX SBOM format as an alternative to CycloneDX.

(Go/Rust ecosystems, CycloneDX SBOM export, the suppression file, SARIF
export, the local hydration cache, and PR auto-commenting have all
moved to V1 — see above.)

## 5. Non-Functional Requirements

- **Zero telemetry**: The tool must never phone home to any endpoint
  other than `api.osv.dev` and, only when the user explicitly passes
  `--pr-comment`, the GitHub API for posting/updating a PR comment (see
  `github_client.py` — the tool's only other network egress point). No
  usage analytics, no license-check network calls.
- **No required API key**: OSV.dev requires none; this is a hard
  constraint, not an implementation detail — do not introduce a paid or
  key-gated dependency as V1's primary data source.
- **Execution speed**: A typical PR-sized diff (1–20 changed dependencies)
  should complete in well under 30 seconds including network round-trips,
  so it doesn't become the slowest step in a CI pipeline. A full-repo
  scan (hundreds of dependencies) should complete in under 2 minutes by
  relying on OSV's batch endpoint (single request for up to ~1000
  packages) rather than one request per package.
- **Rate-limit friendliness**: OSV.dev documents no official hard rate
  limit but the tool must still batch aggressively, use a single HTTP
  session with connection reuse, and back off with exponential delay on
  `429`/`5xx` responses rather than hammering the API on failure.
- **Deterministic exit codes**: `0` = pass, `1` = policy violation found,
  `2` = tool/usage error (bad file, bad git ref). CI systems must be able
  to distinguish "your dependencies are risky" from "the tool itself is
  broken."
- **No silent failure on API outage**: default behavior is fail-closed;
  fail-open is opt-in and must be explicit in both the CLI flag name and
  the documentation, since silently passing a build during a security
  tool's outage is a worse failure mode than a noisy one.
