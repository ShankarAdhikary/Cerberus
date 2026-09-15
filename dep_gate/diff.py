"""
Delta scanning: only report on dependencies that are NEW or CHANGED relative
to a base git ref, instead of the entire lockfile every run.

This is the same trick Dependabot uses to avoid re-flagging pre-existing
vulnerable dependencies on every single PR - a security gate that only
complains about risk YOU just introduced is far less likely to get muted
or bypassed by a frustrated team.

Implementation: use `git show <base_ref>:<path>` to read the lockfile's
content at the base ref (without checking it out or touching the working
tree), parse it with the same lockfile parser used for the current file,
and diff the two dependency sets by (ecosystem, name, version).
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from .lockfile import Dependency, parse_lockfile


class GitDiffError(RuntimeError):
    """Raised when the base ref or file can't be read from git history."""


def _dep_key(dep: Dependency) -> tuple:
    return (dep["ecosystem"], dep["name"], dep["version"])


def get_base_dependencies(filepath: str, base_ref: str) -> list[Dependency]:
    """
    Return the dependency list as it existed in `filepath` at `base_ref`.
    Returns an empty list if the file didn't exist at that ref (e.g. it's
    a brand-new lockfile), rather than treating that as an error.
    """
    try:
        result = subprocess.run(
            ["git", "show", f"{base_ref}:{filepath}"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitDiffError("git is not installed or not on PATH") from exc

    if result.returncode != 0:
        stderr = result.stderr or ""
        # Only a path that's genuinely absent at a *resolvable* ref (new
        # lockfile) is "zero prior dependencies", not an error. Any other
        # failure - an unresolvable ref (bad --base-ref, or a shallow clone
        # missing history per TechSpec.md §4) or not being in a git repo at
        # all - must surface as GitDiffError, never a silent empty diff.
        if "does not exist in" in stderr or "exists on disk, but not in" in stderr:
            return []
        raise GitDiffError(f"git show failed for {base_ref}:{filepath}: {stderr.strip()}")

    # parse_lockfile dispatches on filename, so write the old content to a
    # temp file with the same basename rather than reimplementing dispatch.
    suffix = Path(filepath).name
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / suffix
        tmp_path.write_text(result.stdout, encoding="utf-8")
        return parse_lockfile(str(tmp_path))


def diff_dependencies(filepath: str, base_ref: str) -> list[Dependency]:
    """
    Return only the dependencies in `filepath` that are new or have changed
    version relative to `base_ref`. A version bump counts as "new" because
    the new version could introduce a fresh vulnerability even if the old
    version was clean.
    """
    current = parse_lockfile(filepath)
    base = get_base_dependencies(filepath, base_ref)
    base_keys = {_dep_key(d) for d in base}

    return [dep for dep in current if _dep_key(dep) not in base_keys]
