"""Grype wrapper. Consumes the SBOM produced by Syft."""

from __future__ import annotations

import json
from pathlib import Path

from ossvet.config import INSTALL_HINTS
from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner, safe_run_subprocess


class GrypeScanner(BaseScanner):
    name = "grype"
    required_tool = "grype"

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        if not self.is_available():
            return self._skipped(f"grype not installed. {INSTALL_HINTS['grype']}")
        raw_dir = kwargs.get("raw_dir")
        if not isinstance(raw_dir, Path):
            return self._error("raw_dir kwarg missing")

        sbom_path = raw_dir / "sbom.json"
        target = f"sbom:{sbom_path}" if sbom_path.exists() else f"dir:{repo_path}"

        start = self._now()
        res = safe_run_subprocess(
            ["grype", target, "-o", "json", "-q"],
            timeout=self.timeout,
        )
        if res.error:
            return self._error(f"grype failed: {res.error}", duration=self._now() - start)

        out_path = raw_dir / "grype.json"
        try:
            out_path.write_text(res.stdout, encoding="utf-8")
        except OSError:
            pass

        try:
            data = json.loads(res.stdout) if res.stdout.strip() else {}
        except json.JSONDecodeError:
            return self._error("grype produced unparseable JSON", duration=self._now() - start)

        findings: list[Finding] = []
        for match in (data.get("matches") or []):
            if not isinstance(match, dict):
                continue
            vuln = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            sev_raw = (vuln.get("severity") or "").upper()
            if sev_raw == "CRITICAL":
                category = "cve_critical"
                severity = Severity.CRITICAL
            elif sev_raw == "HIGH":
                category = "cve_high"
                severity = Severity.HIGH
            elif sev_raw == "MEDIUM":
                category = "cve_high_medium_unscored"
                severity = Severity.MEDIUM
            elif sev_raw == "LOW":
                category = "cve_low_unscored"
                severity = Severity.LOW
            else:
                continue

            cve_id = vuln.get("id") or "CVE-?"
            pkg = artifact.get("name") or "?"
            ver = artifact.get("version") or "?"
            findings.append(
                Finding(
                    scanner=self.name,
                    category=category,
                    severity=severity,
                    title=f"{cve_id} in {pkg} {ver}",
                    description=(vuln.get("description") or "")[:400],
                    file_path=artifact.get("locations", [{}])[0].get("path") if isinstance(artifact.get("locations"), list) else None,
                    rule_id=str(cve_id),
                )
            )
        return self._ok(findings, duration=self._now() - start, raw_output_path=str(out_path))
