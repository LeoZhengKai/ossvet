"""Detector for CVE-2021-42574 'Trojan Source' attacks.

Flags BIDI control codepoints, zero-width chars in identifiers, and
Cyrillic homoglyphs in identifiers.
"""

from __future__ import annotations

import re
from pathlib import Path

from ossvet.config import BIDI_CONTROL_CHARS, HOMOGLYPH_CYRILLIC, ZERO_WIDTH_CHARS
from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner, iter_text_files, read_text_safely

# Identifier candidates: alphanumerics + underscore (Python/JS-ish).
# We deliberately allow non-ASCII letters so we can detect Cyrillic
# homoglyphs sitting inside what looks like a valid identifier — and we
# include zero-width characters as part of the run so that a token like
# `pas<ZWSP>swd` is captured as ONE identifier instead of two.
_IDENT_RE = re.compile(
    r"[\w​‌‍⁠﻿]+",
    re.UNICODE,
)


class UnicodeTrojanScanner(BaseScanner):
    name = "unicode_trojan"
    required_tool = None

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        start = self._now()
        findings: list[Finding] = []
        try:
            for path in iter_text_files(repo_path):
                content = read_text_safely(path)
                if content is None:
                    continue
                rel = str(path.relative_to(repo_path))
                self._scan_text(content, rel, findings)
        except Exception as exc:  # noqa: BLE001
            return self._error(f"unicode_trojan scanner failed: {exc!r}", duration=self._now() - start)
        return self._ok(findings, duration=self._now() - start)

    @staticmethod
    def _scan_text(content: str, rel: str, out: list[Finding]) -> None:
        for line_no, line in enumerate(content.splitlines(), 1):
            # 1) BIDI control characters anywhere on the line: HIGH.
            bidi_hits = [c for c in line if c in BIDI_CONTROL_CHARS]
            if bidi_hits:
                names = ", ".join(f"U+{ord(c):04X}" for c in bidi_hits)
                out.append(
                    Finding(
                        scanner="unicode_trojan",
                        category="bidi_control_char",
                        severity=Severity.HIGH,
                        title="Bidirectional Unicode control character (Trojan Source)",
                        description=(
                            f"Line contains BIDI control codepoint(s) {names}. "
                            "Almost always malicious in source code."
                        ),
                        file_path=rel,
                        line_number=line_no,
                        rule_id="CVE-2021-42574-bidi",
                    )
                )

            # 2/3) Zero-width chars or Cyrillic homoglyphs inside identifiers.
            for match in _IDENT_RE.finditer(line):
                token = match.group(0)
                zw_hits = [c for c in token if c in ZERO_WIDTH_CHARS]
                if zw_hits:
                    names = ", ".join(f"U+{ord(c):04X}" for c in zw_hits)
                    out.append(
                        Finding(
                            scanner="unicode_trojan",
                            category="zero_width_in_ident",
                            severity=Severity.HIGH,
                            title="Zero-width character inside identifier",
                            description=(
                                f"Identifier `{token}` contains zero-width codepoint(s) {names}. "
                                "May allow visually-identical but distinct identifiers."
                            ),
                            file_path=rel,
                            line_number=line_no,
                            rule_id="zero-width-ident",
                        )
                    )

                cyr_hits = [c for c in token if c in HOMOGLYPH_CYRILLIC]
                latin_letters = [c for c in token if c.isascii() and c.isalpha()]
                if cyr_hits and latin_letters:
                    names = ", ".join(f"U+{ord(c):04X}" for c in cyr_hits)
                    out.append(
                        Finding(
                            scanner="unicode_trojan",
                            category="homoglyph",
                            severity=Severity.MEDIUM,
                            title="Cyrillic homoglyph inside identifier",
                            description=(
                                f"Identifier `{token}` mixes ASCII letters with Cyrillic homoglyphs {names}."
                            ),
                            file_path=rel,
                            line_number=line_no,
                            rule_id="homoglyph-cyrillic",
                        )
                    )
