"""End-to-end test: scan the malicious fixture, expect BLOCK."""

from __future__ import annotations

from pathlib import Path

from ossvet.main import _scan_path
from ossvet.models import Verdict


def test_malicious_repo_is_blocked(tmp_path: Path) -> None:
    fixtures = Path(__file__).parent / "fixtures" / "malicious_repo"
    output = tmp_path / "reports"
    scan = _scan_path(
        fixtures,
        repo_url="https://github.com/example/evil",
        commit_sha="f" * 40,
        output_dir=output,
        timeout=15,
        use_api=False,
        repo_meta=None,
    )

    # The malicious fixture trips multiple hard-block categories — verdict
    # MUST be BLOCK regardless of which external scanners are installed.
    assert scan.verdict == Verdict.BLOCK or scan.verdict == Verdict.BLOCK.value

    cats = {f.category for f in scan.all_findings}
    # Spot-check a few categories that the pure-Python scanners must catch.
    assert "bidi_control_char" in cats
    assert "reverse_shell" in cats
    assert "crypto_miner" in cats
    assert "npm_install_script" in cats
    assert "setup_py_hook" in cats
    assert "vscode_exec_config" in cats

    # Reports must be produced.
    assert (output / "report.md").is_file()
    assert (output / "report.json").is_file()
    assert (output / "SKILL.md").is_file()
    assert "BLOCK" in (output / "report.md").read_text()


def test_malicious_repo_block_via_override_only(tmp_path: Path, monkeypatch) -> None:
    """Even if scoring without overrides would only reach REVIEW, hard-block
    categories must force BLOCK.

    Implemented as: the bidi_control_char alone (severity HIGH) yields a
    score of 30, which is in the REVIEW band normally. The override pushes
    it to BLOCK.
    """
    repo = tmp_path / "tiny"
    repo.mkdir()
    # A single line containing only a BIDI control char.
    (repo / "x.py").write_text("# ‮\n", encoding="utf-8")

    output = tmp_path / "reports"
    scan = _scan_path(
        repo,
        repo_url="https://github.com/example/tiny",
        commit_sha="a" * 40,
        output_dir=output,
        timeout=10,
        skip=["scorecard", "semgrep", "syft", "grype", "gitleaks", "modelscan"],
        use_api=False,
        repo_meta=None,
    )
    assert scan.verdict == Verdict.BLOCK or scan.verdict == Verdict.BLOCK.value
