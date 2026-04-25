"""Syft wrapper. Generates a CycloneDX/SPDX SBOM that grype consumes."""

from __future__ import annotations

from pathlib import Path

from ossvet.config import INSTALL_HINTS
from ossvet.models import ScannerResult
from ossvet.scanners.base import BaseScanner, safe_run_subprocess


class SyftScanner(BaseScanner):
    name = "syft"
    required_tool = "syft"

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        if not self.is_available():
            return self._skipped(f"syft not installed. {INSTALL_HINTS['syft']}")
        raw_dir = kwargs.get("raw_dir")
        if not isinstance(raw_dir, Path):
            return self._error("raw_dir kwarg missing")
        sbom_path = raw_dir / "sbom.json"

        start = self._now()
        # syft uses `dir:` to point to a filesystem directory.
        res = safe_run_subprocess(
            [
                "syft",
                f"dir:{repo_path}",
                "-o", f"json={sbom_path}",
                "-q",
            ],
            timeout=self.timeout,
        )
        if res.error:
            return self._error(f"syft failed: {res.error}", duration=self._now() - start)
        if res.returncode != 0:
            return self._error(
                f"syft exited {res.returncode}: {res.stderr.strip()[:200]}",
                duration=self._now() - start,
            )
        return self._ok([], duration=self._now() - start, raw_output_path=str(sbom_path))
