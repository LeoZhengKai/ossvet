"""GitHub-provenance signals scanner. Pure-Python; consumes pre-fetched RepoMeta."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ossvet.github_api import RepoMeta
from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # GitHub timestamps look like "2024-01-15T07:23:45Z"
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _days_since(ts: str | None, now: datetime | None = None) -> int | None:
    dt = _parse_iso(ts)
    if dt is None:
        return None
    now = now or datetime.now(timezone.utc)
    return (now - dt).days


class ProvenanceScanner(BaseScanner):
    name = "provenance"
    required_tool = None  # uses prefetched RepoMeta from main.py

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        start = self._now()
        use_api = bool(kwargs.get("use_api", True))
        meta = kwargs.get("repo_meta")
        if not use_api:
            return self._skipped("--no-api set; provenance checks disabled")
        if meta is None or not isinstance(meta, RepoMeta):
            return self._skipped("no RepoMeta available (GitHub API check failed)")

        findings: list[Finding] = []
        try:
            self._check(meta, findings)
        except Exception as exc:  # noqa: BLE001
            return self._error(f"provenance scanner failed: {exc!r}", duration=self._now() - start)
        return self._ok(findings, duration=self._now() - start)

    @staticmethod
    def _check(meta: RepoMeta, out: list[Finding]) -> None:
        # Single contributor.
        if meta.contributor_count_at_least == 1:
            out.append(
                Finding(
                    scanner="provenance",
                    category="single_contributor",
                    severity=Severity.LOW,
                    title="Repo has only one contributor",
                    description="Single-author repos lack peer review and have a higher rate of malicious supply-chain activity.",
                    rule_id="provenance-single-contributor",
                )
            )

        # New maintainer account (< 90 days).
        owner_age = _days_since(meta.owner_created_at)
        if owner_age is not None and owner_age < 90:
            out.append(
                Finding(
                    scanner="provenance",
                    category="new_maintainer_account",
                    severity=Severity.HIGH,
                    title=f"Maintainer account is {owner_age} days old",
                    description="Throwaway-account signal; verify identity before trusting.",
                    rule_id="provenance-new-account",
                )
            )

        # Stale repo (> 180 days since last push).
        push_age = _days_since(meta.pushed_at)
        if push_age is not None and push_age > 180:
            out.append(
                Finding(
                    scanner="provenance",
                    category="stale_repo",
                    severity=Severity.LOW,
                    title=f"Last push was {push_age} days ago",
                    description="Stale repos are at higher risk of unpatched CVEs.",
                    rule_id="provenance-stale",
                )
            )

        # Star velocity (heuristic: > 50 stars/day for a < 30-day repo).
        repo_age = _days_since(meta.created_at)
        if repo_age is not None and 0 < repo_age < 30 and meta.stargazers_count > 1500:
            out.append(
                Finding(
                    scanner="provenance",
                    category="star_velocity_spike",
                    severity=Severity.MEDIUM,
                    title=f"{meta.stargazers_count} stars in {repo_age} days",
                    description="Sudden star spikes can indicate astroturfing.",
                    rule_id="provenance-star-spike",
                )
            )

        # Fork status is noted in SKILL.md identity block; we don't emit a
        # finding for it because it isn't risky on its own.
        _ = meta.is_fork
