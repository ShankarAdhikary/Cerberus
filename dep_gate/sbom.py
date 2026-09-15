"""
Builds a minimal CycloneDX JSON Software Bill of Materials from the list
of dependencies a scan actually looked at.

This is deliberately a plain inventory, independent of vulnerability
findings - an SBOM answers "what's in the build", not "what's risky",
so it's generated straight from lockfile.py's/diff.py's flat Dependency
list rather than from cli.py's findings[]. No dependency graph or
relationships are emitted: the lockfile parsers already collapse to a
flat, deduplicated list and don't track which package depends on which,
so a graph here would just be fabricated.
"""

from __future__ import annotations

from .lockfile import Dependency

CYCLONEDX_SPEC_VERSION = "1.5"

# OSV's ecosystem strings don't always match purl's "type" component
# (https://github.com/package-url/purl-spec) - PyPI/Go/crates.io differ.
_PURL_TYPE_BY_ECOSYSTEM: dict[str, str] = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "golang",
    "crates.io": "cargo",
}


def _purl(dep: Dependency) -> str:
    purl_type = _PURL_TYPE_BY_ECOSYSTEM.get(dep["ecosystem"], dep["ecosystem"].lower())
    return f"pkg:{purl_type}/{dep['name']}@{dep['version']}"


def build_sbom(dependencies: list[Dependency]) -> dict:
    """Build a CycloneDX document (as a plain dict, ready for json.dump)."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": dep["name"],
                "version": dep["version"],
                "purl": _purl(dep),
            }
            for dep in dependencies
        ],
    }
