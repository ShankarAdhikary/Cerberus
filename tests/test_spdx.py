from __future__ import annotations

import json
from pathlib import Path

from dep_gate.spdx import build_spdx


def test_build_spdx_contains_package_inventory() -> None:
    document = build_spdx(
        [{"name": "requests", "version": "2.32.5", "ecosystem": "PyPI"}]
    )

    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["packages"][0]["name"] == "requests"
    assert document["packages"][0]["externalRefs"][0]["referenceLocator"] == (
        "pkg:pypi/requests@2.32.5"
    )


def test_spdx_document_is_json_serializable(tmp_path: Path) -> None:
    output = tmp_path / "report.spdx.json"
    output.write_text(
        json.dumps(build_spdx([]), indent=2),
        encoding="utf-8",
    )

    assert json.loads(output.read_text(encoding="utf-8"))["packages"] == []
