"""All external tools missing → scan must still complete cleanly."""

from __future__ import annotations

from pathlib import Path

import pytest

from ossvet.main import _scan_path, get_scanners
from ossvet.scanners.base import BaseScanner


@pytest.fixture
def force_external_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every scanner with a required_tool report unavailable."""
    original = BaseScanner.is_available

    def fake(self: BaseScanner) -> bool:
        if self.required_tool is None:
            return original(self)
        return False

    monkeypatch.setattr(BaseScanner, "is_available", fake)


def test_doctor_lists_all_scanners() -> None:
    scanners = get_scanners()
    names = {s.name for s in scanners}
    assert names >= {
        "risky_files", "patterns", "unicode_trojan", "dependency_hygiene",
        "provenance", "scorecard", "semgrep", "syft", "grype", "gitleaks",
        "modelscan",
    }


def test_scan_with_no_external_tools(tmp_path: Path, force_external_unavailable: None) -> None:
    fixtures = Path(__file__).parent / "fixtures" / "clean_repo"
    output = tmp_path / "reports"
    scan = _scan_path(
        fixtures,
        repo_url="https://github.com/example/clean",
        commit_sha="0" * 40,
        output_dir=output,
        timeout=10,
        use_api=False,
        repo_meta=None,
    )

    # Every external scanner must report skipped (not error).
    for r in scan.scanner_results:
        if r.scanner_name in {"scorecard", "semgrep", "syft", "grype", "gitleaks", "modelscan"}:
            assert r.status in {"skipped", "ok"}, (
                f"{r.scanner_name} reported {r.status}: {r.error_message}"
            )

    # Pure-Python scanners must have produced an `ok` result.
    statuses = {r.scanner_name: r.status for r in scan.scanner_results}
    for name in ("risky_files", "patterns", "unicode_trojan", "dependency_hygiene"):
        assert statuses[name] == "ok"


def test_malicious_repo_still_blocked_without_external_tools(
    tmp_path: Path, force_external_unavailable: None
) -> None:
    """The override rule must drive BLOCK even with no external scanners."""
    fixtures = Path(__file__).parent / "fixtures" / "malicious_repo"
    output = tmp_path / "reports"
    scan = _scan_path(
        fixtures,
        repo_url="https://github.com/example/evil",
        commit_sha="f" * 40,
        output_dir=output,
        timeout=10,
        use_api=False,
        repo_meta=None,
    )
    from ossvet.models import Verdict
    assert scan.verdict in {Verdict.BLOCK, Verdict.BLOCK.value}
