from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from dep_gate.project import discover_lockfiles, prepare_project_input


def test_discover_lockfiles_recurses_and_skips_generated_directories(
    tmp_path: Path,
) -> None:
    (tmp_path / "services" / "api").mkdir(parents=True)
    (tmp_path / "services" / "api" / "requirements.txt").write_text(
        "requests==2.32.5\n", encoding="utf-8"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package-lock.json").touch()

    assert discover_lockfiles(tmp_path) == [
        str(tmp_path / "services" / "api" / "requirements.txt")
    ]


def test_prepare_project_input_extracts_zip_and_discovers_files(tmp_path: Path) -> None:
    source = tmp_path / "project.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("app/package-lock.json", '{"packages": {}}')

    files, cleanup = prepare_project_input(source)
    try:
        assert len(files) == 1
        assert Path(files[0]).name == "package-lock.json"
        assert Path(files[0]).is_file()
    finally:
        cleanup.cleanup()


def test_prepare_project_input_rejects_zip_path_traversal(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("../outside.txt", "unsafe")

    with pytest.raises(ValueError, match="Unsafe ZIP entry"):
        prepare_project_input(source)


def test_prepare_project_input_rejects_invalid_zip(tmp_path: Path) -> None:
    source = tmp_path / "invalid.zip"
    source.write_text("not a zip archive", encoding="utf-8")

    with pytest.raises(ValueError, match="Unable to read project ZIP"):
        prepare_project_input(source)


def test_prepare_project_input_rejects_empty_project(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Project path must be a directory"):
        prepare_project_input(tmp_path / "missing-project")
