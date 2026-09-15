"""
Tests for dep_gate.sbom — pure, I/O-free document construction (no network,
no filesystem). Covers the CycloneDX shape and purl mapping for every
supported ecosystem.
"""

from __future__ import annotations

from dep_gate.sbom import CYCLONEDX_SPEC_VERSION, build_sbom


def test_build_sbom_empty_dependency_list() -> None:
    sbom = build_sbom([])

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == CYCLONEDX_SPEC_VERSION
    assert sbom["components"] == []


def test_build_sbom_npm_purl() -> None:
    deps = [{"name": "lodash", "version": "4.17.15", "ecosystem": "npm"}]

    sbom = build_sbom(deps)

    assert sbom["components"] == [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.15",
            "purl": "pkg:npm/lodash@4.17.15",
        }
    ]


def test_build_sbom_pypi_purl_uses_lowercase_pypi_type() -> None:
    deps = [{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}]

    sbom = build_sbom(deps)

    assert sbom["components"][0]["purl"] == "pkg:pypi/requests@2.31.0"


def test_build_sbom_go_purl_uses_golang_type() -> None:
    deps = [{"name": "golang.org/x/crypto", "version": "v0.17.0", "ecosystem": "Go"}]

    sbom = build_sbom(deps)

    assert sbom["components"][0]["purl"] == "pkg:golang/golang.org/x/crypto@v0.17.0"


def test_build_sbom_crates_io_purl_uses_cargo_type() -> None:
    deps = [{"name": "smallvec", "version": "1.6.1", "ecosystem": "crates.io"}]

    sbom = build_sbom(deps)

    assert sbom["components"][0]["purl"] == "pkg:cargo/smallvec@1.6.1"


def test_build_sbom_preserves_dependency_order() -> None:
    deps = [
        {"name": "a", "version": "1.0.0", "ecosystem": "npm"},
        {"name": "b", "version": "2.0.0", "ecosystem": "npm"},
    ]

    sbom = build_sbom(deps)

    assert [c["name"] for c in sbom["components"]] == ["a", "b"]
