# Rules.md — AI Coding Agent Standards

These rules are binding for any AI agent (or human) contributing code to
this repository. They exist because this is a security tool: correctness
and predictability matter more here than in typical application code —
a false pass in this tool is a security incident waiting to happen, and
a false fail erodes team trust in the gate until someone disables it.

## 1. Code Style

- **Strict PEP 8.** Line length 100 cols max (not the PEP 8 default 79 —
  this project's dict/type-hint-heavy code is more readable slightly
  wider). Run `black` and `ruff` (or `flake8`) before considering any
  change complete.
- **Type hints on every function signature, no exceptions**, including
  return types (`-> None`, `-> List[Dependency]`, `-> Optional[str]`).
  `from __future__ import annotations` at the top of every module so
  forward references and `X | None` syntax work regardless of the
  minimum supported Python version.
- **Docstrings on every public function and module**, explaining *why*,
  not just *what*, whenever the "why" isn't obvious from the code alone
  (e.g. `osv_client.py`'s module docstring explains the batch-then-hydrate
  rationale — a bare "queries OSV" docstring would not have prevented the
  common integration bug this project deliberately avoids).
- Prefer `TypedDict`/`NamedTuple`/`dataclass` over bare `dict`/`tuple` for
  any structure passed between modules (see `Schema.md`). Bare dicts are
  acceptable only for the final JSON-serialization boundary.

## 2. Security Rules

- **No hardcoded paths.** Every file path is a parameter or CLI argument;
  never assume `package-lock.json` lives at a fixed absolute path, and
  never hardcode a developer's local filesystem layout in committed code.
- **`subprocess` calls must use list-form arguments, never `shell=True`,
  and never string-interpolate untrusted input into a command.** The one
  `subprocess` call in this codebase (`diff.py`'s `git show
  {base_ref}:{filepath}`) passes `base_ref` and `filepath` as separate
  list elements to `subprocess.run(["git", "show", f"{base_ref}:{filepath}"], ...)`
  — note even here the ref and path are joined with a literal `:` inside
  one list element per git's own CLI syntax, not concatenated into a
  shell string that a shell would interpret. If `base_ref` or `filepath`
  can ever come from an untrusted source (e.g. a PR title or external
  webhook payload) in a future feature, they must be validated against
  an allow-list pattern before being passed to `git`.
- **Sanitize all external input at the boundary it enters the system**:
  lockfile contents (could be adversarially crafted — deeply nested JSON,
  absurdly long lines), OSV API responses (treat every field as
  `Optional`/possibly-absent, never assume a key exists — see
  `severity.py`'s defensive `.get()` usage throughout), and any future
  webhook/PR-comment input in V2.
- **Never introduce a network call outside `osv_client.py`** (and, for
  V2's PR commenting, a clearly-named `github_client.py`) without
  updating `PRD.md`'s zero-telemetry non-functional requirement and
  calling it out explicitly in the PR description — network egress in a
  security tool is a reviewable surface, not an implementation detail.
- **Never log or print full API tokens/credentials**, including in debug
  output; if V2's GitHub PR commenting is implemented, redact tokens in
  any error message that might include request headers.

## 3. Testing Rules

- **Write tests for parsers and evaluators (`lockfile.py`, `severity.py`,
  `diff.py`) before considering that module "done"** — these are pure,
  deterministic, network-free functions with no excuse for undertested
  edge cases. `osv_client.py` is tested with a mocked `requests.Session`;
  a real network call is never part of the default test run.
- Every bug fix must come with a regression test reproducing the bug
  first (test fails before the fix, passes after) — this applies
  especially to OSV schema-mapping bugs, since the API's own issue
  tracker shows the schema has previously shipped inconsistencies (e.g.
  `severity[].type` documented as a string enum but observed as an
  integer in some responses) — this codebase's parsing of that field
  must not assume the schema doc and the live API always agree.
- Test the exit-code contract explicitly: exit `0` on pass, `1` on a
  policy violation, `2` on a usage/tool error. A test suite that only
  checks "no exception was raised" without asserting the exact exit code
  is insufficient for a CI gate tool.

## 4. Agent Behavior Rules

- **Never leave `TODO`, `FIXME`, `pass  # placeholder`, or `...` stub
  bodies in code presented as complete.** If a feature is genuinely
  out of scope for the current phase, it belongs in `Tracker.md`'s To Do
  section, not as dead code in the module.
- **Only modify the file(s) the current task actually requires.** Do not
  "helpfully" refactor unrelated modules, rename unrelated variables, or
  reformat files outside the current diff's scope — this makes PR review
  of a security tool's changes harder, not easier.
- **Do not implement V2 features while a V1 phase's exit criteria (per
  `ImplementationPlan.md`) are still unmet.** Building the PR-commenting
  feature before the core gate has a real test suite, for example, is
  scope creep that this project explicitly rejects.
- **When the OSV API schema and this project's assumptions conflict**
  (discovered via a failing integration check or a new API response
  shape), update `Schema.md` and `TechSpec.md` in the same change as the
  code fix — these documents are meant to stay authoritative, not
  aspirational.
- **Ask before adding a new third-party dependency.** `requests`, `cvss`,
  and `rich` are the currently approved dependencies; each addition
  expands the CI attack surface for a *security* tool, which deserves
  more scrutiny than an ordinary app dependency.
- **Exit codes and the `SCAN FAILED`/`SCAN PASSED` literal summary line
  are a public contract** (documented in `AppFlow.md` and `Design.md`)
  — do not change their wording or exit-code meanings without updating
  every doc in this `docs/` folder in the same change, since downstream
  CI configs and any future tooling may depend on them verbatim.
