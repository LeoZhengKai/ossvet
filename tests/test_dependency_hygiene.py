"""Dependency-hygiene scanner tests."""

from __future__ import annotations

import json
from pathlib import Path

from ossvet.scanners.dependency_hygiene import DependencyHygieneScanner


def test_typosquat_flagged_python(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("import requestes\n", encoding="utf-8")
    result = DependencyHygieneScanner().run(repo)
    cats = {f.category for f in result.findings}
    assert "typosquat_suspect" in cats
    titles = " ".join(f.title for f in result.findings)
    assert "requestes" in titles


def test_typosquat_double_l(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "x.py").write_text("from python_dateutill import parser\n", encoding="utf-8")
    result = DependencyHygieneScanner().run(repo)
    titles = " ".join(f.title for f in result.findings)
    assert "python_dateutill" in titles or "python-dateutill" in titles


def test_legitimate_import_not_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "x.py").write_text("import requests\nfrom flask import Flask\n", encoding="utf-8")
    result = DependencyHygieneScanner().run(repo)
    typosquats = [f for f in result.findings if f.category == "typosquat_suspect"]
    assert typosquats == []


def test_unpinned_python_requirement(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests\nflask>=2.0\n", encoding="utf-8")
    result = DependencyHygieneScanner().run(repo)
    cats = {f.category for f in result.findings}
    assert "unpinned_deps" in cats


def test_pinned_python_requirement_not_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\nflask==2.3.0\n", encoding="utf-8")
    result = DependencyHygieneScanner().run(repo)
    unpinned = [f for f in result.findings if f.category == "unpinned_deps"]
    assert unpinned == []


def test_npm_caret_unpinned(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^18.0.0"}}),
        encoding="utf-8",
    )
    result = DependencyHygieneScanner().run(repo)
    cats = {f.category for f in result.findings}
    assert "unpinned_deps" in cats


def test_npm_pinned_not_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"react": "18.0.0"}}),
        encoding="utf-8",
    )
    result = DependencyHygieneScanner().run(repo)
    unpinned = [f for f in result.findings if f.category == "unpinned_deps"]
    assert unpinned == []


def test_typosquat_js(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    # `lodahs` ~ `lodash` (Levenshtein 1).
    (repo / "x.js").write_text("const _ = require('lodahs');\n", encoding="utf-8")
    result = DependencyHygieneScanner().run(repo)
    titles = " ".join(f.title for f in result.findings)
    assert "lodahs" in titles


def test_short_module_names_not_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "x.py").write_text("import os\nimport re\n", encoding="utf-8")
    result = DependencyHygieneScanner().run(repo)
    typosquats = [f for f in result.findings if f.category == "typosquat_suspect"]
    assert typosquats == []
