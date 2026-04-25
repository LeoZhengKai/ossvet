"""ModelScan wrapper. Only runs when the repo contains ML weight files."""

from __future__ import annotations

import json
from pathlib import Path

from ossvet.config import INSTALL_HINTS, ML_WEIGHT_EXTENSIONS
from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner, safe_run_subprocess


def _has_model_files(repo: Path) -> bool:
    for ext in ML_WEIGHT_EXTENSIONS:
        # rglob is recursive; iterate so we can short-circuit.
        for _ in repo.rglob(f"*{ext}"):
            return True
    return False


class ModelScanScanner(BaseScanner):
    name = "modelscan"
    required_tool = "modelscan"

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        if not _has_model_files(repo_path):
            return self._skipped("no ML weight files in repo")
        if not self.is_available():
            return self._skipped(f"modelscan not installed. {INSTALL_HINTS['modelscan']}")

        raw_dir = kwargs.get("raw_dir")
        if not isinstance(raw_dir, Path):
            return self._error("raw_dir kwarg missing")
        out_path = raw_dir / "modelscan.json"

        start = self._now()
        res = safe_run_subprocess(
            ["modelscan", "-p", str(repo_path), "--json", "-o", str(out_path)],
            timeout=self.timeout,
        )
        if res.error:
            return self._error(f"modelscan failed: {res.error}", duration=self._now() - start)
        if not out_path.exists():
            # Some modelscan versions print JSON to stdout instead.
            try:
                out_path.write_text(res.stdout, encoding="utf-8")
            except OSError:
                pass
        try:
            data = json.loads(out_path.read_text(encoding="utf-8") or "{}")
        except (OSError, json.JSONDecodeError):
            return self._error("modelscan produced unparseable JSON", duration=self._now() - start)

        findings: list[Finding] = []
        issues = (data.get("issues") if isinstance(data, dict) else None) or []
        if isinstance(issues, list):
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                sev_raw = (issue.get("severity") or "").upper()
                if sev_raw not in {"CRITICAL", "HIGH"}:
                    continue
                severity = Severity.CRITICAL if sev_raw == "CRITICAL" else Severity.HIGH
                category = "modelscan_high"
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=category,
                        severity=severity,
                        title=f"ModelScan {sev_raw}: {issue.get('description', 'unsafe operator')}",
                        description=(issue.get("operator") or issue.get("description") or "")[:300],
                        file_path=str(issue.get("source") or issue.get("file") or ""),
                        rule_id=str(issue.get("scanner") or "modelscan"),
                    )
                )

        # Note: also flag the raw presence of unsafe model formats (.pkl, .pt) as an
        # informational `unsafe_model_format` finding even if modelscan's parser
        # cleared them. We only do this when the file actually exists on disk.
        for ext in {".pkl", ".pt", ".pth", ".joblib", ".ckpt"}:
            for path in repo_path.rglob(f"*{ext}"):
                if any(p in {".git", "node_modules"} for p in path.parts):
                    continue
                findings.append(
                    Finding(
                        scanner=self.name,
                        category="unsafe_model_format",
                        severity=Severity.MEDIUM,
                        title=f"Pickle-based model weight: {path.name}",
                        description="Pickle-format models execute arbitrary code on load. Prefer .safetensors.",
                        file_path=str(path.relative_to(repo_path)),
                        rule_id="unsafe-pickle",
                    )
                )
                break  # one finding per extension is enough
        return self._ok(findings, duration=self._now() - start, raw_output_path=str(out_path))
