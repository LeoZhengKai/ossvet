"""OpenSSF Scorecard wrapper.

Scorecard requires a public GitHub URL (it queries the API itself). It
runs against a remote URL, not the local clone, so we accept `repo_url`
via kwargs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ossvet.config import INSTALL_HINTS
from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner, safe_run_subprocess


class ScorecardScanner(BaseScanner):
    name = "scorecard"
    required_tool = "scorecard"

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        if not self.is_available():
            return self._skipped(f"scorecard not installed. {INSTALL_HINTS['scorecard']}")
        if not kwargs.get("use_api", True):
            return self._skipped("--no-api set; scorecard requires GitHub API access")

        repo_url = kwargs.get("repo_url")
        if not isinstance(repo_url, str) or not repo_url.startswith("https://github.com/"):
            return self._error("scorecard requires a GitHub repo URL")

        raw_dir = kwargs.get("raw_dir")
        if not isinstance(raw_dir, Path):
            return self._error("raw_dir kwarg missing")

        start = self._now()
        # scorecard reads GITHUB_AUTH_TOKEN; pass through environment.
        env = os.environ.copy()
        res = safe_run_subprocess(
            [
                "scorecard",
                "--repo", repo_url,
                "--format", "json",
                "--show-details=false",
            ],
            timeout=self.timeout,
            env=env,
        )
        if res.error:
            return self._error(f"scorecard failed: {res.error}", duration=self._now() - start)
        if res.returncode != 0 or not res.stdout.strip():
            return self._error(
                f"scorecard exited {res.returncode}: {res.stderr.strip()[:200]}",
                duration=self._now() - start,
            )

        out_path = raw_dir / "scorecard.json"
        try:
            out_path.write_text(res.stdout, encoding="utf-8")
        except OSError:
            pass

        try:
            data = json.loads(res.stdout)
        except json.JSONDecodeError:
            return self._error("scorecard produced unparseable JSON", duration=self._now() - start)

        findings: list[Finding] = []
        checks = data.get("checks") if isinstance(data, dict) else None
        if isinstance(checks, list):
            for chk in checks:
                if not isinstance(chk, dict):
                    continue
                score = chk.get("score")
                if not isinstance(score, int):
                    continue
                if score >= 0 and score <= 2:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            # No scoring category — surfaced for human review only.
                            category="scorecard_low",
                            severity=Severity.HIGH,
                            title=f"Scorecard `{chk.get('name', 'check')}` scored {score}/10",
                            description=(chk.get("reason") or "")[:300],
                            rule_id=str(chk.get("name") or "scorecard"),
                        )
                    )
        return self._ok(findings, duration=self._now() - start, raw_output_path=str(out_path))
