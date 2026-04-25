"""Grep-style scanner for suspicious code patterns. Pure-Python."""

from __future__ import annotations

import re
from pathlib import Path

from ossvet.config import (
    PATTERN_CATEGORY,
    PATTERN_SEVERITY,
    SUSPICIOUS_PATTERNS,
)
from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner, iter_text_files, read_text_safely

_COMPILED: dict[str, re.Pattern[str]] = {
    name: re.compile(rx) for name, rx in SUSPICIOUS_PATTERNS.items()
}

_SEVERITY_MAP = {s.value: s for s in Severity}


class PatternsScanner(BaseScanner):
    name = "patterns"
    required_tool = None

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        start = self._now()
        findings: list[Finding] = []
        try:
            for path in iter_text_files(repo_path):
                content = read_text_safely(path)
                if content is None:
                    continue
                rel = path.relative_to(repo_path)
                for line_no, line in enumerate(content.splitlines(), 1):
                    if len(line) > 4000:
                        # absurdly long minified line; skip
                        continue
                    for name, regex in _COMPILED.items():
                        match = regex.search(line)
                        if not match:
                            continue
                        category = PATTERN_CATEGORY[name]
                        sev_str = PATTERN_SEVERITY[category]
                        findings.append(
                            Finding(
                                scanner=self.name,
                                category=category,
                                severity=_SEVERITY_MAP[sev_str],
                                title=f"Suspicious pattern: {name}",
                                description=f"Matched `{name}` ({category}) on a single line: {line.strip()[:200]}",
                                file_path=str(rel),
                                line_number=line_no,
                                rule_id=name,
                            )
                        )
        except Exception as exc:  # noqa: BLE001
            return self._error(f"patterns scanner failed: {exc!r}", duration=self._now() - start)

        return self._ok(findings, duration=self._now() - start)
