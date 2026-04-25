"""Report-writer tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ossvet.models import Finding, ScanResult, ScannerResult, Severity, Verdict
from ossvet.reporting import write_json, write_markdown, write_skill_md


def _scan(findings: list[Finding] | None = None) -> ScanResult:
    findings = findings or []
    return ScanResult(
        repo_url="https://github.com/example/test",  # type: ignore[arg-type]
        commit_sha="abc1234567890",
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        duration_seconds=1.5,
        scanner_results=[
            ScannerResult(scanner_name="patterns", status="ok", tool_available=True, findings=findings),
        ],
        all_findings=findings,
        risk_score=42,
        verdict=Verdict.REVIEW,
        summary=["finding-1", "finding-2"],
    )


def test_write_json_round_trip(tmp_path: Path) -> None:
    f = Finding(scanner="x", category="cve_high", severity=Severity.HIGH, title="t", description="d")
    scan = _scan([f])
    out = tmp_path / "report.json"
    write_json(scan, out)
    data = json.loads(out.read_text())
    assert data["risk_score"] == 42
    assert data["verdict"] == Verdict.REVIEW.value
    assert len(data["all_findings"]) == 1


def test_write_markdown_contains_key_sections(tmp_path: Path) -> None:
    f = Finding(
        scanner="patterns",
        category="reverse_shell",
        severity=Severity.CRITICAL,
        title="reverse-shell match",
        description="a reverse shell pattern",
        file_path="src/x.py",
        line_number=42,
    )
    scan = _scan([f])
    out = tmp_path / "report.md"
    write_markdown(scan, out)
    text = out.read_text()
    assert "# OSS Vet Report" in text
    assert "Verdict: REVIEW REQUIRED" in text
    assert "## Top Findings" in text
    assert "src/x.py" in text
    assert "## Findings by Category" in text
    assert "## Scanner Status" in text
    assert "## Recommended Next Actions" in text


def test_write_skill_md(tmp_path: Path) -> None:
    scan = _scan()
    out = tmp_path / "SKILL.md"
    write_skill_md(scan, None, out)
    text = out.read_text()
    assert "# SKILL.md" in text
    assert "abc1234567890" in text
    assert "## Vetting log" in text
    assert "Sandboxed runtime test: pending" in text


def test_write_skill_md_handles_no_findings_gracefully(tmp_path: Path) -> None:
    scan = _scan([])
    out = tmp_path / "SKILL.md"
    write_skill_md(scan, None, out)
    text = out.read_text()
    assert "Install-time hooks present: no" in text


def test_markdown_no_findings(tmp_path: Path) -> None:
    scan = ScanResult(
        repo_url="https://github.com/example/test",  # type: ignore[arg-type]
        commit_sha="def4567890",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_seconds=0.5,
        scanner_results=[],
        all_findings=[],
        risk_score=0,
        verdict=Verdict.LOW_RISK,
        summary=[],
    )
    out = tmp_path / "report.md"
    write_markdown(scan, out)
    text = out.read_text()
    assert "LOW RISK" in text
    assert "No notable findings" in text
