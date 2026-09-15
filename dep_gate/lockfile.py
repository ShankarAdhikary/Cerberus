"""
Lockfile parsers.

Each parser returns a list of dicts: {"name": str, "version": str, "ecosystem": str}

Ecosystem strings must exactly match OSV.dev's canonical ecosystem names
(case-sensitive): "npm", "PyPI", "Go", "crates.io", "Maven", "RubyGems", "Packagist".
See: https://ossf.github.io/osv-schema/#ecosystems
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TypedDict

import tomllib


class Dependency(TypedDict):
    name: str
    version: str
    ecosystem: str


def parse_npm_lockfile(filepath: str) -> list[Dependency]:
    """
    Parse npm lockfile v2/v3 format (the 'packages' key), which is what
    `npm install` has produced since npm 7+. Falls back to the legacy
    'dependencies' key (lockfile v1) if 'packages' is absent.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    deps: list[Dependency] = []

    if "packages" in data:
        for pkg_path, pkg_data in data["packages"].items():
            # The root project is keyed as "" - skip it.
            if pkg_path == "":
                continue
            version = pkg_data.get("version")
            if not version:
                # Can happen for "link" entries (local workspace packages) - skip.
                continue
            name = pkg_path.rsplit("node_modules/", 1)[-1]
            deps.append({"name": name, "version": version, "ecosystem": "npm"})
    elif "dependencies" in data:
        _walk_legacy_deps(data["dependencies"], deps)
    else:
        raise ValueError(
            f"{filepath} does not look like a recognized npm lockfile "
            "(no 'packages' or 'dependencies' key found)"
        )

    return _dedupe(deps)


def _walk_legacy_deps(dep_tree: dict, out: list[Dependency]) -> None:
    """Recursively walk npm lockfile v1's nested 'dependencies' tree."""
    for name, meta in dep_tree.items():
        version = meta.get("version")
        if version:
            out.append({"name": name, "version": version, "ecosystem": "npm"})
        nested = meta.get("dependencies")
        if nested:
            _walk_legacy_deps(nested, out)


# Matches lines like: requests==2.28.0, requests>=2.28.0, requests (== 2.28.0)
_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+-]+)"
)


def parse_requirements_txt(filepath: str) -> list[Dependency]:
    """
    Parse a pip 'requirements.txt' (ideally one produced by `pip freeze`
    or `pip-compile`, since only pinned '==' entries have a resolvable
    version). Unpinned or VCS/URL requirements are skipped with a note,
    since OSV needs an exact version to check.
    """
    deps: list[Dependency] = []
    skipped: list[str] = []

    with open(filepath, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            match = _REQ_LINE_RE.match(line)
            if match:
                name, version = match.groups()
                deps.append({"name": name, "version": version, "ecosystem": "PyPI"})
            else:
                skipped.append(line)

    if skipped:
        print(
            f"Skipped {len(skipped)} unpinned/non-standard requirement line(s) "
            "(no exact version to check): "
            + ", ".join(skipped[:5])
            + (" ..." if len(skipped) > 5 else "")
        )

    return _dedupe(deps)


def parse_cargo_lock(filepath: str) -> list[Dependency]:
    """
    Parse a Rust `Cargo.lock` (TOML) into a flat list of dependencies.
    Only `[[package]]` entries with a `registry+` `source` (crates.io) are
    included - path dependencies (workspace members, which have no
    `source` key at all) and git dependencies (`source` starts with
    `git+`) aren't published to crates.io and have no meaningful version
    to check against OSV.
    """
    with open(filepath, "rb") as f:
        data = tomllib.load(f)

    deps: list[Dependency] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source", "")
        if not name or not version or not source.startswith("registry+"):
            continue
        deps.append({"name": name, "version": version, "ecosystem": "crates.io"})

    return _dedupe(deps)


_GO_MOD_SUFFIX = "/go.mod"


def parse_go_sum(filepath: str) -> list[Dependency]:
    """
    Parse a Go module `go.sum` file: lines of `module version[/go.mod] hash`.
    Each module normally appears twice - once for its content hash and once
    for its go.mod file's hash (the "/go.mod" suffix on the version field) -
    so both rows must resolve to the same (module, version) dependency and
    collapse via `_dedupe()`. Some indirect modules appear with only the
    "/go.mod" row (no content hash needed for the build), and those still
    count as part of the module graph, so they aren't skipped.
    """
    deps: list[Dependency] = []

    with open(filepath, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3:
                # Malformed/unexpected line shape - skip rather than crash,
                # consistent with how requirements.txt handles stray lines.
                continue
            module, version_field, _hash = parts
            version = version_field.removesuffix(_GO_MOD_SUFFIX)
            deps.append({"name": module, "version": version, "ecosystem": "Go"})

    return _dedupe(deps)


def _dedupe(deps: list[Dependency]) -> list[Dependency]:
    seen = set()
    unique: list[Dependency] = []
    for dep in deps:
        key = (dep["ecosystem"], dep["name"], dep["version"])
        if key not in seen:
            seen.add(key)
            unique.append(dep)
    return unique


def parse_lockfile(filepath: str) -> list[Dependency]:
    """Auto-detect lockfile type from filename and dispatch to the right parser."""
    name = Path(filepath).name.lower()
    if name == "package-lock.json":
        return parse_npm_lockfile(filepath)
    if name == "go.sum":
        return parse_go_sum(filepath)
    if name == "cargo.lock":
        return parse_cargo_lock(filepath)
    if name.endswith(".txt"):
        return parse_requirements_txt(filepath)
    raise ValueError(
        f"Unrecognized lockfile type for '{filepath}'. "
        "Supported: package-lock.json, requirements.txt, go.sum, Cargo.lock"
    )
