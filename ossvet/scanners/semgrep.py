"""Semgrep wrapper. Runs `--config=auto` and `--config=p/supply-chain`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ossvet.config import INSTALL_HINTS
from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner, safe_run_subprocess


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    required_tool = "semgrep"

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        if not self.is_available():
            return self._skipped(f"semgrep not installed. {INSTALL_HINTS['semgrep']}")
        raw_dir = kwargs.get("raw_dir")
        if not isinstance(raw_dir, Path):
            return self._error("raw_dir kwarg missing")

        start = self._now()
        all_findings: list[Finding] = []
        configs = ["auto", "p/supply-chain"]

        merged: dict[str, Any] = {"results": []}
        for cfg in configs:
            res = safe_run_subprocess(
                [
                    "semgrep",
                    "--config", cfg,
                    "--json",
                    "--quiet",
                    "--metrics=off",
                    "--timeout", str(max(5, self.timeout - 5)),
                    "--", str(repo_path),
                ],
                timeout=self.timeout,
            )
            if res.error:
                # First config error fatal; second config error tolerated.
                if cfg == "auto":
                    return self._error(f"semgrep failed: {res.error}", duration=self._now() - start)
                continue
            if res.returncode not in (0, 1):
                if cfg == "auto":
                    return self._error(
                        f"semgrep exited {res.returncode}: {res.stderr.strip()[:200]}",
                        duration=self._now() - start,
                    )
                continue
            try:
                data = json.loads(res.stdout) if res.stdout.strip() else {}
            except json.JSONDecodeError:
                continue
            results = data.get("results") if isinstance(data, dict) else None
            if isinstance(results, list):
                merged["results"].extend(results)

        raw_path = raw_dir / "semgrep.json"
        try:
            raw_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        except OSError:
            pass

        for r in merged["results"]:
            if not isinstance(r, dict):
                continue
            extra = r.get("extra") or {}
            sev_raw = (extra.get("severity") or "").upper()
            if sev_raw not in {"ERROR", "WARNING"}:
                continue
            category = "semgrep_error" if sev_raw == "ERROR" else "semgrep_warning"
            severity = Severity.HIGH if sev_raw == "ERROR" else Severity.MEDIUM
            file_path = r.get("path") or "<unknown>"
            try:
                file_path = str(Path(file_path).relative_to(repo_path))
            except ValueError:
                pass
            line = (r.get("start") or {}).get("line") if isinstance(r.get("start"), dict) else None
            all_findings.append(
                Finding(
                    scanner=self.name,
                    category=category,
                    severity=severity,
                    title=f"semgrep: {r.get('check_id', 'rule')}",
                    description=(extra.get("message") or "")[:500],
                    file_path=str(file_path),
                    line_number=int(line) if isinstance(line, int) else None,
                    rule_id=r.get("check_id"),
                )
            )

        return self._ok(all_findings, duration=self._now() - start, raw_output_path=str(raw_path))
