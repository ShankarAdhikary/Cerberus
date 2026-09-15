"""Shared pytest fixtures for the dep_gate test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Root directory holding static test fixture files."""
    return FIXTURES_DIR
