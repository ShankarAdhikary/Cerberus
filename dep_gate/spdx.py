"""Build a minimal SPDX 2.3 document from scanned dependencies."""

from __future__ import annotations

from datetime import UTC, datetime

from .lockfile import Dependency


def build_spdx(dependencies: list[Dependency]) -> dict:
    """Build an SPDX inventory without fabricating dependency relationships."""
    packages = []
    for index, dep in enumerate(dependencies, start=1):
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{index}",
                "name": dep["name"],
                "versionInfo": dep["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "supplier": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": _purl(dep),
                    }
                ],
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "dep-gate-scan",
        "documentNamespace": "https://github.com/ShankarAdhikary/Cerberus/dep-gate",
        "creationInfo": {
            "created": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: dep-gate"],
        },
        "packages": packages,
    }


def _purl(dep: Dependency) -> str:
    types = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "crates.io": "cargo"}
    return f"pkg:{types.get(dep['ecosystem'], dep['ecosystem'].lower())}/{dep['name']}@{dep['version']}"
