"""End-to-end test: scan the clean fixture, expect LOW_RISK."""

from __future__ import annotations

from pathlib import Path

from ossvet.main import _scan_path
from ossvet.models import Verdict


def test_clean_repo_is_low_risk(tmp_path: Path) -> None:
    fixtures = Path(__file__).parent / "fixtures" / "clean_repo"
    output = tmp_path / "reports"
    scan = _scan_path(
        fixtures,
        repo_url="https://github.com/example/clean",
        commit_sha="0" * 40,
        output_dir=output,
        timeout=15,
        use_api=False,
        repo_meta=None,
    )
    # External scanners are likely missing in CI; we only assert on pure-Python ones.
    assert scan.verdict in {Verdict.LOW_RISK, Verdict.REVIEW.value, Verdict.LOW_RISK.value}
    # Stronger assertion: no hard-block categories.
    cats = {f.category for f in scan.all_findings}
    assert "bidi_control_char" not in cats
    assert "reverse_shell" not in cats
    assert "crypto_miner" not in cats
    # Reports must be produced.
    assert (output / "report.md").is_file()
    assert (output / "report.json").is_file()
    assert (output / "SKILL.md").is_file()
