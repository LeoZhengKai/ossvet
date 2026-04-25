"""Gitleaks wrapper for secret scanning."""

from __future__ import annotations

import json
from pathlib import Path

from ossvet.config import INSTALL_HINTS
from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner, safe_run_subprocess


class GitleaksScanner(BaseScanner):
    name = "gitleaks"
    required_tool = "gitleaks"

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        if not self.is_available():
            return self._skipped(f"gitleaks not installed. {INSTALL_HINTS['gitleaks']}")
        raw_dir = kwargs.get("raw_dir")
        if not isinstance(raw_dir, Path):
            return self._error("raw_dir kwarg missing")

        start = self._now()
        out_path = raw_dir / "gitleaks.json"
        res = safe_run_subprocess(
            [
                "gitleaks", "detect",
                "--source", str(repo_path),
                "--report-format", "json",
                "--report-path", str(out_path),
                "--no-git",
                "--exit-code", "0",
                "--no-banner",
            ],
            timeout=self.timeout,
        )
        if res.error:
            return self._error(f"gitleaks failed: {res.error}", duration=self._now() - start)

        if not out_path.exists():
            return self._ok([], duration=self._now() - start, raw_output_path=str(out_path))

        try:
            data = json.loads(out_path.read_text(encoding="utf-8") or "[]")
        except (OSError, json.JSONDecodeError):
            data = []

        findings: list[Finding] = []
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                rule = item.get("RuleID") or item.get("Rule") or "secret"
                file_rel = item.get("File") or "<unknown>"
                try:
                    file_rel = str(Path(file_rel).relative_to(repo_path))
                except ValueError:
                    pass
                # Gitleaks doesn't have a 'verified' bit by default, but some
                # rules (e.g. AWS, Slack) have entropy + format; treat any
                # non-generic rule as 'verified'.
                rule_lower = str(rule).lower()
                category = (
                    "verified_secret"
                    if any(brand in rule_lower for brand in ("aws", "slack", "github", "stripe", "twilio", "google"))
                    else "unverified_secret"
                )
                severity = Severity.HIGH if category == "verified_secret" else Severity.MEDIUM
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=category,
                        severity=severity,
                        title=f"Possible secret: {rule}",
                        description=(item.get("Description") or "")[:300],
                        file_path=str(file_rel),
                        line_number=item.get("StartLine"),
                        rule_id=str(rule),
                    )
                )
        return self._ok(findings, duration=self._now() - start, raw_output_path=str(out_path))
