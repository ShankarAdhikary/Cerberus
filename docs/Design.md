# Design.md — Terminal UI & Output Design

## 1. Design Principles

- **CI-log-first, terminal-second.** The primary consumer of this output
  is a scrollback buffer in a CI web UI, not an interactive terminal. All
  color/formatting must degrade to legible plain text when piped to a
  non-TTY (Rich handles this automatically when `Console()` detects no
  TTY, but never assume — test with `| cat`).
- **Severity is the primary visual axis.** Every table, summary line, and
  PR comment leads with severity, not package name, because that's what
  a reviewer scans for first.
- **No spinners on deterministic-length work.** A progress spinner is
  only justified for the network-bound batch query / hydration calls
  (unknown wall-clock time); parsing and evaluation are near-instant and
  should not spin.

## 2. Color & Typography Mapping (Rich)

| Severity | Rich style | Rationale |
|---|---|---|
| `CRITICAL` | `bold white on red` | Highest-contrast, impossible to miss in a scrollback. |
| `HIGH` | `bold red` | Distinct from CRITICAL but still urgent-read. |
| `MODERATE` | `yellow` | Caution, not blocking by default (`--fail-on high` default). |
| `LOW` | `cyan` | Informational. |
| `UNKNOWN` | `dim white` | De-emphasized; visible but not alarming, since it isn't a confirmed severity. |
| Pass state (`✅`-equivalent text) | `bold green` | Reserved solely for the final "SCAN PASSED" line. |
| Fail state | `bold red` | Reserved solely for the final "SCAN FAILED" line. |

Avoid raw emoji as the sole signal (screen readers and some CI log
renderers strip or mis-render them) — pair any emoji with the plain-text
word (`SCAN FAILED`, not just `❌`).

## 3. Terminal Layout

### 3.1 Progress indicator (during API calls)
```
⠋ Scanning 47 dependencies against OSV.dev ...
```
A single `rich.status.Status` spinner (not a multi-step progress bar —
there are exactly two network phases, batch and hydrate, which is too
coarse-grained to usefully subdivide visually).

### 3.2 Findings table
```
                  Dependency Vulnerability Findings
┏━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Package ┃ Version ┃ Severity ┃ Vuln ID        ┃ Fix                ┃
┡━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ lodash  │ 4.17.15 │ HIGH     │ GHSA-fake-1234 │ upgrade to 4.17.19 │
└─────────┴─────────┴──────────┴────────────────┴────────────────────┘
```
Column order is fixed: Package, Version, Severity, Vuln ID, Fix.
Severity column text uses the color mapping in §2. Rows are sorted
severity-descending so the worst finding is always visible without
scrolling, even if the table is long. "Fix" column reads either
`upgrade to {version}` or `no fix yet` — never blank, since a blank cell
reads as a rendering bug rather than "no fix available."

With `--verbose`, a sixth **Source** column is appended after Fix
(`Severity.source`, e.g. `CVSS_V3 vector` or `database_specific.severity`)
— appended, not inserted, so the base five-column contract above holds
unchanged for every non-verbose run. The plain-text fallback appends the
same information as `(source: {source})` at the end of each line. In
both cases this is purely additive: `--verbose` never changes a finding's
severity, fix recommendation, or the scan's exit code.

With `--ignore-file`, a finding matched by an active suppression stays in
the table (never hidden — see PRD.md's auditability requirement) but its
**Severity** cell gets a `(suppressed)` suffix, e.g. `HIGH (suppressed)`
— a value change within the existing Severity column, not a new column,
so this composes cleanly with `--verbose`'s extra column. A separate
summary line after the table (`Suppressed (not blocking): N finding(s)
via PATH.`) states how many were suppressed and by which file, for the
same reason the grep-able `SCAN FAILED`/`SCAN PASSED` line exists —
someone scanning CI output shouldn't have to open the ignore file to
notice suppressions are in effect.

### 3.3 Summary line (always the final line of output)
```
SCAN FAILED: 2 finding(s) at or above 'high'.
```
or
```
SCAN PASSED: no findings at or above the configured threshold.
```
This line must be `grep`-able verbatim (`SCAN FAILED` / `SCAN PASSED`
as a fixed literal prefix) so downstream tooling can parse CI logs
without depending on the JSON artifact.

### 3.4 Diff-mode preamble
```
Diff mode: 3 new/changed dependency(ies) vs origin/main.
```
Printed before the scanning line whenever `--diff-only` is active, so a
reader immediately understands why the dependency count is smaller than
the full lockfile.

## 4. GitHub PR Comment Design (`--pr-comment`, opt-in)

`github_client.render_pr_comment()` produces this exact structure:

```markdown
## 🔒 Dependency Vulnerability Gate

**Result:** ❌ Failed — 2 finding(s) at or above `high`

| Severity | Package | Vuln ID | Fix |
|---|---|---|---|
| 🔴 CRITICAL | `requests@2.25.0` | GHSA-xxxx | Upgrade to `2.31.0` |
| 🟠 HIGH | `lodash@4.17.15` | GHSA-yyyy | Upgrade to `4.17.19` |

<details>
<summary>Scan details</summary>

- Scanned: 47 dependencies (diff-only vs `origin/main`)
- Threshold: `--fail-on high`
- Full report: see the `dependency-vulnerability-report` build artifact

</details>
```

Design rules for this comment (enforced by `render_pr_comment()`/`upsert_comment()`):
- The comment is **idempotent per-PR** — `upsert_comment()` finds the
  existing bot comment via a hidden `COMMENT_MARKER` and `PATCH`es it on
  re-runs, rather than appending a new comment on every push.
- The `<details>` block keeps the comment short by default; the table
  above the fold shows only blocking findings, not every `LOW`/`UNKNOWN`
  finding.
- Never include a raw CVSS vector string in the comment body — it's
  noise for a non-security reviewer; the severity word and score are
  sufficient, with the full record left to the JSON artifact.
- A comment-posting failure never changes the scan's own exit code (see
  `AppFlow.md` §3/§4) — this output is additive, not a gate in itself.
