"""
Tests for dep_gate.diff — uses a real temp-dir git repository (not mocked)
per Phase 5 exit criteria, since the whole point of this module is its
interaction with actual `git show` subprocess behavior.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from dep_gate.diff import GitDiffError, diff_dependencies, get_base_dependencies

LOCKFILE_NAME = "package-lock.json"


def _npm_lockfile(deps: dict[str, str]) -> str:
    packages = {"": {"name": "sample", "version": "1.0.0"}}
    for name, version in deps.items():
        packages[f"node_modules/{name}"] = {"version": version}
    return json.dumps({"name": "sample", "lockfileVersion": 3, "packages": packages})


def _run_git(args: list, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """
    A real git repo with two commits on 'main':
      base:    lodash@4.17.15
      feature: lodash@4.17.19 (bumped), left-pad@1.3.0 (new)
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(["init", "-b", "main"], repo)
    _run_git(["config", "user.email", "test@example.com"], repo)
    _run_git(["config", "user.name", "Test"], repo)

    lockfile = repo / LOCKFILE_NAME
    lockfile.write_text(_npm_lockfile({"lodash": "4.17.15"}), encoding="utf-8")
    _run_git(["add", LOCKFILE_NAME], repo)
    _run_git(["commit", "-m", "base"], repo)

    lockfile.write_text(_npm_lockfile({"lodash": "4.17.19", "left-pad": "1.3.0"}), encoding="utf-8")
    _run_git(["add", LOCKFILE_NAME], repo)
    _run_git(["commit", "-m", "feature: bump lodash, add left-pad"], repo)

    return repo


def test_get_base_dependencies_reads_content_at_ref(
    git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `git show ref:path` takes a repo-relative pathspec, so exercise this
    # the way the CLI actually invokes it: cwd at the repo root.
    monkeypatch.chdir(git_repo)
    base_deps = get_base_dependencies(LOCKFILE_NAME, "HEAD~1")

    assert {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"} in base_deps
    assert len(base_deps) == 1


def test_get_base_dependencies_returns_empty_list_when_file_absent_at_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo2"
    repo.mkdir()
    _run_git(["init", "-b", "main"], repo)
    _run_git(["config", "user.email", "test@example.com"], repo)
    _run_git(["config", "user.name", "Test"], repo)
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    _run_git(["add", "README.md"], repo)
    _run_git(["commit", "-m", "no lockfile yet"], repo)

    lockfile = repo / LOCKFILE_NAME
    lockfile.write_text(_npm_lockfile({"lodash": "4.17.19"}), encoding="utf-8")
    _run_git(["add", LOCKFILE_NAME], repo)
    _run_git(["commit", "-m", "add brand-new lockfile"], repo)

    monkeypatch.chdir(repo)
    base_deps = get_base_dependencies(LOCKFILE_NAME, "HEAD~1")

    assert base_deps == []


def test_diff_dependencies_catches_version_bump_and_new_dep(
    git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(git_repo)
    changed = diff_dependencies(LOCKFILE_NAME, "HEAD~1")
    names_versions = {(d["name"], d["version"]) for d in changed}

    assert ("lodash", "4.17.19") in names_versions  # version bump treated as new
    assert ("left-pad", "1.3.0") in names_versions  # brand new dependency
    assert len(changed) == 2


def test_diff_dependencies_excludes_untouched_deps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo3"
    repo.mkdir()
    _run_git(["init", "-b", "main"], repo)
    _run_git(["config", "user.email", "test@example.com"], repo)
    _run_git(["config", "user.name", "Test"], repo)

    lockfile = repo / LOCKFILE_NAME
    lockfile.write_text(_npm_lockfile({"lodash": "4.17.15", "left-pad": "1.3.0"}), encoding="utf-8")
    _run_git(["add", LOCKFILE_NAME], repo)
    _run_git(["commit", "-m", "base"], repo)

    # Only lodash bumps; left-pad is untouched and must be excluded from the diff.
    lockfile.write_text(_npm_lockfile({"lodash": "4.17.19", "left-pad": "1.3.0"}), encoding="utf-8")
    _run_git(["add", LOCKFILE_NAME], repo)
    _run_git(["commit", "-m", "bump lodash only"], repo)

    monkeypatch.chdir(repo)
    changed = diff_dependencies(LOCKFILE_NAME, "HEAD~1")

    assert [d["name"] for d in changed] == ["lodash"]


def test_get_base_dependencies_missing_git_binary_raises_git_diff_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise_not_found(*args, **kwargs):
        raise FileNotFoundError("git not found")

    monkeypatch.setattr(subprocess, "run", _raise_not_found)

    with pytest.raises(GitDiffError):
        get_base_dependencies(str(tmp_path / LOCKFILE_NAME), "HEAD~1")


def test_get_base_dependencies_outside_git_repo_raises_git_diff_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression test: TechSpec.md §4 requires a git command failure (not a
    # repo, unresolvable ref, shallow clone) to surface as GitDiffError, not
    # be silently treated the same as "file legitimately absent at that ref".
    non_repo = tmp_path / "not-a-repo"
    non_repo.mkdir()
    monkeypatch.chdir(non_repo)

    with pytest.raises(GitDiffError):
        get_base_dependencies(LOCKFILE_NAME, "HEAD~1")


def test_get_base_dependencies_unresolvable_ref_raises_git_diff_error(
    git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression test: an unknown/unresolvable base ref (e.g. a typo, or a
    # shallow clone missing history) must raise, not silently return [].
    monkeypatch.chdir(git_repo)

    with pytest.raises(GitDiffError):
        get_base_dependencies(LOCKFILE_NAME, "origin/does-not-exist-branch")
