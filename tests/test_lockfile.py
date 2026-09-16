"""
Tests for dep_gate.lockfile — fully network-free per Phase 1 exit criteria.

Covers npm lockfile v1 (legacy 'dependencies'), v2 (both keys present,
'packages' must win), v3 ('packages'-only), transitive/nested deps, and
requirements.txt with pinned/unpinned/comment/VCS lines.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dep_gate.lockfile import (
    parse_cargo_lock,
    parse_go_sum,
    parse_lockfile,
    parse_npm_lockfile,
    parse_requirements_txt,
)


def test_parse_npm_v3_extracts_top_level_and_transitive(fixtures_dir: Path) -> None:
    deps = parse_npm_lockfile(str(fixtures_dir / "npm_v3" / "package-lock.json"))

    assert {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"} in deps
    assert {"name": "nested-transitive", "version": "1.2.3", "ecosystem": "npm"} in deps
    assert len(deps) == 2


def test_parse_npm_v3_skips_root_and_link_entries(fixtures_dir: Path) -> None:
    deps = parse_npm_lockfile(str(fixtures_dir / "npm_v3" / "package-lock.json"))
    names = [d["name"] for d in deps]

    assert "sample-app" not in names
    assert "workspace-link" not in names


def test_parse_npm_v2_prefers_packages_key_over_legacy_dependencies(fixtures_dir: Path) -> None:
    deps = parse_npm_lockfile(str(fixtures_dir / "npm_v2" / "package-lock.json"))

    assert {"name": "requests-like", "version": "2.0.0", "ecosystem": "npm"} in deps
    assert {"name": "deep-dep", "version": "0.9.9", "ecosystem": "npm"} in deps
    assert len(deps) == 2


def test_parse_npm_v1_walks_legacy_nested_dependencies(fixtures_dir: Path) -> None:
    deps = parse_npm_lockfile(str(fixtures_dir / "npm_v1" / "package-lock.json"))

    assert {"name": "legacy-pkg", "version": "3.3.3", "ecosystem": "npm"} in deps
    assert {"name": "legacy-transitive", "version": "1.0.0", "ecosystem": "npm"} in deps
    assert {"name": "top-level-only", "version": "5.0.0", "ecosystem": "npm"} in deps
    assert len(deps) == 3


def test_parse_npm_lockfile_rejects_unrecognized_json(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text('{"name": "no-deps-or-packages-key"}', encoding="utf-8")

    with pytest.raises(ValueError):
        parse_npm_lockfile(str(bad))


def test_parse_requirements_txt_pinned_lines(fixtures_dir: Path) -> None:
    deps = parse_requirements_txt(str(fixtures_dir / "requirements_mixed.txt"))

    assert {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"} in deps
    assert {"name": "lodash-clone", "version": "1.0.0", "ecosystem": "PyPI"} in deps
    assert {"name": "numpy", "version": "1.26.4", "ecosystem": "PyPI"} in deps


def test_parse_requirements_txt_skips_unpinned_and_vcs_lines(fixtures_dir: Path) -> None:
    deps = parse_requirements_txt(str(fixtures_dir / "requirements_mixed.txt"))
    names = [d["name"] for d in deps]

    assert "flask" not in names
    assert "django" not in names
    assert not any("git+" in n for n in names)
    assert len(deps) == 3


def test_parse_requirements_txt_warns_on_skipped_lines(
    fixtures_dir: Path, capsys: pytest.CaptureFixture
) -> None:
    parse_requirements_txt(str(fixtures_dir / "requirements_mixed.txt"))
    captured = capsys.readouterr()

    assert "Skipped" in captured.out
    assert "flask" in captured.out


def test_parse_requirements_txt_dedupes(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\nrequests==2.28.0\n", encoding="utf-8")

    deps = parse_requirements_txt(str(req))

    assert deps == [{"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"}]


def test_parse_go_sum_collapses_content_and_go_mod_hash_lines(fixtures_dir: Path) -> None:
    # Each module normally appears twice (content hash + "/go.mod" hash);
    # both rows share the same module@version and must collapse to one dep.
    deps = parse_go_sum(str(fixtures_dir / "go.sum"))

    assert {"name": "github.com/BurntSushi/toml", "version": "v0.3.1", "ecosystem": "Go"} in deps
    assert {"name": "github.com/pkg/errors", "version": "v0.9.1", "ecosystem": "Go"} in deps
    assert len(deps) == 3


def test_parse_go_sum_includes_go_mod_only_modules(fixtures_dir: Path) -> None:
    # golang.org/x/sys in the fixture has only a "/go.mod" line (no content
    # hash) - it's still part of the module graph and must not be dropped.
    deps = parse_go_sum(str(fixtures_dir / "go.sum"))
    names = [d["name"] for d in deps]

    assert "golang.org/x/sys" in names
    match = next(d for d in deps if d["name"] == "golang.org/x/sys")
    assert match["version"] == "v0.0.0-20191026070338-33540a1f6037"


def test_parse_go_sum_skips_malformed_lines(tmp_path: Path) -> None:
    go_sum = tmp_path / "go.sum"
    go_sum.write_text("not a valid line\ngithub.com/pkg/errors v0.9.1 h1:abc=\n", encoding="utf-8")

    deps = parse_go_sum(str(go_sum))

    assert deps == [{"name": "github.com/pkg/errors", "version": "v0.9.1", "ecosystem": "Go"}]


def test_parse_go_sum_skips_blank_lines(tmp_path: Path) -> None:
    go_sum = tmp_path / "go.sum"
    go_sum.write_text(
        "\ngithub.com/pkg/errors v0.9.1 h1:abc=\n\n\n", encoding="utf-8"
    )

    deps = parse_go_sum(str(go_sum))

    assert deps == [{"name": "github.com/pkg/errors", "version": "v0.9.1", "ecosystem": "Go"}]


def test_parse_lockfile_dispatches_go_sum(fixtures_dir: Path) -> None:
    deps = parse_lockfile(str(fixtures_dir / "go.sum"))

    assert all(d["ecosystem"] == "Go" for d in deps)
    assert len(deps) == 3


def test_parse_cargo_lock_extracts_registry_packages(fixtures_dir: Path) -> None:
    deps = parse_cargo_lock(str(fixtures_dir / "Cargo.lock"))

    assert {"name": "serde", "version": "1.0.195", "ecosystem": "crates.io"} in deps
    assert {"name": "serde_derive", "version": "1.0.195", "ecosystem": "crates.io"} in deps


def test_parse_cargo_lock_skips_path_and_git_dependencies(fixtures_dir: Path) -> None:
    # "sample-app" (workspace root) and "local-crate" have no registry
    # `source` at all (path deps); "git-dep" has a "git+" source, not
    # "registry+". None are resolvable against OSV's crates.io ecosystem.
    deps = parse_cargo_lock(str(fixtures_dir / "Cargo.lock"))
    names = [d["name"] for d in deps]

    assert "sample-app" not in names
    assert "local-crate" not in names
    assert "git-dep" not in names
    assert len(deps) == 2


def test_parse_cargo_lock_missing_package_table_returns_empty(tmp_path: Path) -> None:
    cargo_lock = tmp_path / "Cargo.lock"
    cargo_lock.write_text("version = 3\n", encoding="utf-8")

    deps = parse_cargo_lock(str(cargo_lock))

    assert deps == []


def test_parse_lockfile_dispatches_cargo_lock(fixtures_dir: Path) -> None:
    deps = parse_lockfile(str(fixtures_dir / "Cargo.lock"))

    assert all(d["ecosystem"] == "crates.io" for d in deps)
    assert len(deps) == 2


def test_parse_lockfile_dispatches_on_filename(fixtures_dir: Path) -> None:
    npm_deps = parse_lockfile(str(fixtures_dir / "npm_v3" / "package-lock.json"))
    txt_deps = parse_lockfile(str(fixtures_dir / "requirements_mixed.txt"))

    assert all(d["ecosystem"] == "npm" for d in npm_deps)
    assert all(d["ecosystem"] == "PyPI" for d in txt_deps)


def test_parse_lockfile_unrecognized_extension_raises(tmp_path: Path) -> None:
    unknown = tmp_path / "deps.yaml"
    unknown.write_text("name: foo\n", encoding="utf-8")

    with pytest.raises(ValueError):
        parse_lockfile(str(unknown))


def test_parse_lockfile_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "package-lock.json"

    with pytest.raises(FileNotFoundError):
        parse_lockfile(str(missing))
