"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """A blank temp directory representing a fake cloned repo."""
    repo = tmp_path / "repo"
    repo.mkdir()
    return repo
