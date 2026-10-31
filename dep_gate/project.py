"""Project input discovery for local folder and ZIP-based CLI scans."""

from __future__ import annotations

import os
import tempfile
import zipfile
from pathlib import Path

SUPPORTED_FILENAMES = frozenset(
    {
        "package-lock.json",
        "requirements.txt",
        "go.sum",
        "cargo.lock",
        "pom.xml",
        "gemfile.lock",
        "composer.lock",
    }
)
_SKIP_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "__pycache__"}


def discover_lockfiles(project_dir: str | Path) -> list[str]:
    """Find supported lockfiles below a project directory deterministically."""
    root = Path(project_dir).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {project_dir}")

    files: list[str] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in _SKIP_DIRECTORIES and not name.startswith(".")
        )
        for filename in sorted(filenames):
            if filename.lower() in SUPPORTED_FILENAMES:
                files.append(str(Path(current_root) / filename))
    return files


def extract_project_zip(
    zip_path: str | Path,
) -> tuple[str, tempfile.TemporaryDirectory]:
    """Safely extract a project ZIP and return its directory plus cleanup handle."""
    source = Path(zip_path).expanduser().resolve()
    if not source.is_file() or source.suffix.lower() != ".zip":
        raise ValueError(
            f"Project ZIP does not exist or is not a .zip file: {zip_path}"
        )

    temporary_directory = tempfile.TemporaryDirectory(prefix="dep-gate-project-")
    destination = Path(temporary_directory.name).resolve()
    try:
        with zipfile.ZipFile(source) as archive:
            for member in archive.infolist():
                target = (destination / member.filename).resolve()
                if target != destination and destination not in target.parents:
                    raise ValueError(
                        f"Unsafe ZIP entry outside extraction directory: {member.filename}"
                    )
            archive.extractall(destination)
    except (OSError, zipfile.BadZipFile) as exc:
        temporary_directory.cleanup()
        raise ValueError(f"Unable to read project ZIP {zip_path}: {exc}") from exc
    return str(destination), temporary_directory


def prepare_project_input(
    project_path: str | Path,
) -> tuple[list[str], tempfile.TemporaryDirectory | None]:
    """Discover lockfiles in a folder or safely extracted ZIP project."""
    path = Path(project_path).expanduser()
    if path.is_dir():
        return discover_lockfiles(path), None
    if path.is_file() and path.suffix.lower() == ".zip":
        extracted_path, cleanup = extract_project_zip(path)
        try:
            files = discover_lockfiles(extracted_path)
        except Exception:
            cleanup.cleanup()
            raise
        return files, cleanup
    raise ValueError(f"Project path must be a directory or .zip file: {project_path}")


def cleanup_project_input(cleanup: tempfile.TemporaryDirectory | None) -> None:
    if cleanup is not None:
        cleanup.cleanup()
