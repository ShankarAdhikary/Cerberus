# Schema.md — Data Models & Interfaces

There is no database in this project — all state is in-memory for the
duration of a single CLI invocation. This document defines the canonical
in-memory shapes and how raw OSV.dev JSON maps onto them. Current code
uses `TypedDict`/`NamedTuple` for lightness; Pydantic equivalents are
given alongside for teams that prefer runtime validation.

## 1. `Dependency`

Represents one resolved package + version extracted from a lockfile.

**Current (`dep_gate/lockfile.py`, `TypedDict`):**
```python
class Dependency(TypedDict):
    name: str
    version: str
    ecosystem: str  # must be an OSV canonical ecosystem string
```

**Pydantic equivalent (for stricter validation if migrated):**
```python
from pydantic import BaseModel, field_validator

VALID_ECOSYSTEMS = {"npm", "PyPI", "Go", "crates.io", "Maven", "RubyGems", "Packagist"}

class Dependency(BaseModel):
    name: str
    version: str
    ecosystem: str

    @field_validator("ecosystem")
    @classmethod
    def ecosystem_must_be_canonical(cls, v: str) -> str:
        if v not in VALID_ECOSYSTEMS:
            raise ValueError(f"'{v}' is not a canonical OSV ecosystem string")
        return v
```

**Uniqueness key** used throughout the codebase (dedup, diffing, lookup):
`(ecosystem, name, version)` tuple, also rendered as the string key
`f"{ecosystem}/{name}@{version}"` in `osv_client.py`'s batch result map.

## 2. `Vulnerability` (internal finding record)

Represents one dependency-to-vulnerability match, after hydration and
severity evaluation. This is the shape written to `--json` output and
displayed in the findings table.

**Current (`dep_gate/cli.py`, plain dict, informally structured):**
```python
{
    "package": str,
    "version": str,
    "ecosystem": str,
    "vuln_id": str,              # e.g. "GHSA-jf85-cpcp-j695"
    "severity": str,              # "UNKNOWN" | "LOW" | "MODERATE" | "HIGH" | "CRITICAL"
    "cvss_score": float | None,   # populated only when a parseable CVSS vector existed
    "fixed_version": str | None,  # None if no fix has been published yet
    "summary": str,               # from the OSV record's top-level "summary" field
    "source": str,                 # OPTIONAL: only present when --verbose is set;
                                    # see Severity.source below
    "suppressed": bool,             # OPTIONAL: only present when --ignore-file is set
    "suppression_reason": str | None,  # OPTIONAL: only present when --ignore-file is set;
                                        # the matching Suppression.reason, or None if not suppressed
    "source_file": str,             # OPTIONAL: only present when --file was given more than
                                     # once (a multi-file scan) - which lockfile this finding
                                     # came from. Deliberately absent on a single-file scan
                                     # (verbatim `args.files[0]`, not present at all as a key)
                                     # rather than always-present-but-usually-trivial: a field
                                     # that's the same value on every record for the overwhelming
                                     # majority of invocations (anyone scanning one lockfile) adds
                                     # noise for zero information, and Rules.md's byte-compat
                                     # contract for the single-file case requires it be absent
                                     # anyway - see TechSpec.md §2.10.
}
```

**Pydantic equivalent:**
```python
from typing import Optional
from pydantic import BaseModel

class Vulnerability(BaseModel):
    package: str
    version: str
    ecosystem: str
    vuln_id: str
    severity: str
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    summary: str = ""
    source: Optional[str] = None  # only set when --verbose is passed
    suppressed: Optional[bool] = None  # only set when --ignore-file is passed
    suppression_reason: Optional[str] = None  # only set when --ignore-file is passed
    source_file: Optional[str] = None  # only set on a multi-file scan (--file given 2+ times)
```

## 3. `Severity` (evaluator output, before assembly into a Vulnerability)

**Current (`dep_gate/severity.py`, `NamedTuple`):**
```python
class Severity(NamedTuple):
    level: str            # one of LEVELS = ["UNKNOWN","LOW","MODERATE","HIGH","CRITICAL"]
    score: Optional[float]  # numeric CVSS base score, or None
    source: str            # e.g. "CVSS_V3 vector", "database_specific.severity", "no severity data"
```
`source` exists purely for transparency/debugging. It's always computed
by `severity.assess()`, but only copied into the `Vulnerability` dict (and
thus surfaced in the table/JSON output) when `--verbose` is passed — see
`AppFlow.md`'s flags table and `Design.md` §3.2.

## 3.5 `Suppression` (`.dep-gate-ignore.yml` entry, `suppress.py`)

**Current (`dep_gate/suppress.py`, `NamedTuple`):**
```python
class Suppression(NamedTuple):
    vuln_id: str
    package: Optional[str]  # None = suppress this vuln_id for any package
    expires: str            # YYYY-MM-DD, validated at load time
    reason: str             # required, non-blank justification
```
Loaded once per run by `suppress.load_suppressions()`, which raises
`ValueError`/`FileNotFoundError` (never silently skips a bad entry) for
a missing file, a missing required field, a blank `reason`, or an
unparseable `expires` date. `suppress.find_active_suppression(vuln_id,
package, suppressions, today=...)` returns the first matching entry
whose `expires` is still `>= today` (ISO-8601 dates compare correctly as
plain strings, so no date-object arithmetic is needed), or `None`.

## 4. `ScanReport` (top-level result — currently implicit in `cli.run()`, not yet a formal object)

Recommended formalization if the CLI grows additional output formats
(e.g. SARIF for V2's GitHub code-scanning integration):

```python
from typing import List
from pydantic import BaseModel

class ScanReport(BaseModel):
    total_scanned: int
    findings: List[Vulnerability]
    fail_on_threshold: str
    exit_code: int          # 0, 1, or 2 — see AppFlow.md §2
    diff_mode: bool
    base_ref: Optional[str] = None  # only set when diff_mode is True
```

## 5. OSV.dev JSON → Internal Model Mapping

### 5.1 Batch response → vuln ID set
```
OSV /v1/querybatch response:
{
  "results": [
    {"vulns": [{"id": "GHSA-...", "modified": "..."}]}
  ]
}
                    │
                    ▼  (osv_client.batch_query)
{"npm/lodash@4.17.15": {"GHSA-..."}}   # Dict[str, set[str]]
```
Only the `id` field is used from this response; `modified` is discarded.
The implemented hydration cache (`cache.py`, `--cache-file`) does not use
it — it uses a fixed TTL instead, to avoid changing this function's
return shape; see `TechSpec.md` §2.8 for the reasoning.

### 5.2 Hydrated vuln record → `Severity`
```
OSV /v1/vulns/{id} response (relevant subset):
{
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/.../A:N"}],
  "affected": [{
      "package": {"ecosystem": "npm", "name": "lodash"},
      "database_specific": {"severity": "HIGH"},
      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]
  }]
}
                    │
                    ▼  (severity.assess)
Severity(level="HIGH", score=7.5, source="CVSS_V3 vector")
```
Precedence order (see `TechSpec.md` §2.3): a parseable CVSS vector always
wins over a `database_specific.severity` string if both are present,
since the vector is a quantitative score vs. a coarser qualitative label.

### 5.3 Hydrated vuln record → fixed version
```
                    │
                    ▼  (severity.fixed_version, filtered by ecosystem+name)
"4.17.19"
```
Only `ranges[].events[].fixed` entries belonging to the *matching*
`affected[].package` are considered — a record can list `affected`
blocks for multiple packages/ecosystems, and mixing them up would
produce an incorrect upgrade recommendation.

**Multiple ranges for the same package.** A record can also cover
multiple *disjoint* vulnerable ranges for the same matching package —
confirmed against the live API on `GHSA-43w2-9j62-hq99`
(smallvec@crates.io), which lists two separate `affected` blocks: one
for the 0.x branch (`introduced: "0.6.3"`, `fixed: "0.6.14"`) and one
for the 1.x branch (`introduced: "1.0.0"`, `fixed: "1.6.1"`). Its
RUSTSEC-2021-0003 alias record expresses the identical two branches
differently — as a *single* `ranges` entry with two `introduced`/`fixed`
event pairs back to back, rather than two `affected` blocks. Both shapes
occur in real responses. `fixed_version()` therefore takes an optional
`installed_version` argument and only returns a fix from the range that
actually contains it; without that argument (or if no range matches) it
falls back to the numeric-lowest fix across every range, which is the
behavior that originally produced a misleading "upgrade to 0.6.14"
recommendation for a package pinned at `1.6.0`.
