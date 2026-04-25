"""Risk-score aggregation and verdict computation."""

from __future__ import annotations

from collections.abc import Iterable

from ossvet.config import HARD_BLOCK_CATEGORIES, SCORING_WEIGHTS, VERDICT_THRESHOLDS
from ossvet.models import Finding, Severity, Verdict


def compute_risk(findings: Iterable[Finding]) -> tuple[int, Verdict]:
    """Return (risk_score, verdict) for a flat list of findings.

    Algorithm (PRD §7):
      * For each finding, look up its scoring category in SCORING_WEIGHTS.
      * Add per_finding to the category bucket, capped at the category cap.
      * Total = min(sum of bucket scores, 100).
      * Verdict is the band that contains the total.
      * Override: any finding in HARD_BLOCK_CATEGORIES → Verdict.BLOCK.
      * Override: any finding with category 'modelscan_high' AND severity
        CRITICAL → Verdict.BLOCK.
    """
    score_by_cat: dict[str, int] = {}
    has_modelscan_critical = False
    has_hard_block = False

    for f in findings:
        cat = f.category
        if cat in HARD_BLOCK_CATEGORIES:
            has_hard_block = True
        if cat == "modelscan_high":
            sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
            if sev is Severity.CRITICAL:
                has_modelscan_critical = True

        cfg = SCORING_WEIGHTS.get(cat)
        if cfg is None:
            continue
        bumped = score_by_cat.get(cat, 0) + cfg["per_finding"]
        score_by_cat[cat] = min(bumped, cfg["cap"])

    total = min(sum(score_by_cat.values()), 100)

    verdict = _verdict_for_score(total)
    if has_hard_block or has_modelscan_critical:
        verdict = Verdict.BLOCK
    return total, verdict


def _verdict_for_score(score: int) -> Verdict:
    for name, (lo, hi) in VERDICT_THRESHOLDS.items():
        if lo <= score <= hi:
            return Verdict[name]
    # Should be unreachable since thresholds cover 0..100.
    return Verdict.BLOCK


# Annotate each finding with its score_contribution. Used for report ordering.
def annotate_findings(findings: list[Finding]) -> None:
    """Mutates findings in place, setting `score_contribution` per category cap."""
    used_by_cat: dict[str, int] = {}
    for f in findings:
        cfg = SCORING_WEIGHTS.get(f.category)
        if cfg is None:
            f.score_contribution = 0
            continue
        remaining = cfg["cap"] - used_by_cat.get(f.category, 0)
        contribution = max(0, min(cfg["per_finding"], remaining))
        used_by_cat[f.category] = used_by_cat.get(f.category, 0) + contribution
        f.score_contribution = contribution
