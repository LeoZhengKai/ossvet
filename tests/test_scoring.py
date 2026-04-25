"""Scoring + verdict tests. Targets 100% coverage of ossvet/scoring.py."""

from __future__ import annotations

import pytest

from ossvet.models import Finding, Severity, Verdict
from ossvet.scoring import annotate_findings, compute_risk


def _f(category: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        scanner="test",
        category=category,
        severity=severity,
        title=f"test-{category}",
        description="x",
    )


def test_no_findings_is_low_risk() -> None:
    score, verdict = compute_risk([])
    assert score == 0
    assert verdict is Verdict.LOW_RISK


def test_unknown_category_is_ignored() -> None:
    score, verdict = compute_risk([_f("nonexistent_category")])
    assert score == 0
    assert verdict is Verdict.LOW_RISK


def test_per_category_cap_applies() -> None:
    # cve_critical: per_finding=10, cap=30 → 5 findings should still cap at 30.
    findings = [_f("cve_critical", Severity.CRITICAL) for _ in range(5)]
    score, _ = compute_risk(findings)
    assert score == 30


def test_total_score_clamped_to_100() -> None:
    # Stack many max-cap categories; total should never exceed 100.
    findings: list[Finding] = []
    for cat in ("cve_critical", "verified_secret", "credential_targeting",
                "modelscan_high", "typosquat_suspect"):
        for _ in range(10):
            findings.append(_f(cat, Severity.HIGH))
    score, _ = compute_risk(findings)
    assert score == 100


def test_thresholds_low_review_block() -> None:
    # 0 → LOW_RISK
    s0, v0 = compute_risk([])
    assert v0 is Verdict.LOW_RISK and s0 == 0

    # ~30 (cve_critical capped) → REVIEW
    s30, v30 = compute_risk([_f("cve_critical", Severity.CRITICAL) for _ in range(3)])
    assert s30 == 30 and v30 is Verdict.REVIEW

    # Stack to 60+ → BLOCK (without using a hard-block category)
    findings = [
        _f("cve_critical", Severity.CRITICAL),  # +10
        _f("cve_critical", Severity.CRITICAL),  # +10
        _f("cve_critical", Severity.CRITICAL),  # +10 (cap 30)
        _f("verified_secret", Severity.HIGH),   # +15
        _f("verified_secret", Severity.HIGH),   # +15 (so far 60)
    ]
    s, v = compute_risk(findings)
    assert s >= 60
    assert v is Verdict.BLOCK


def test_hard_block_bidi_overrides_low_score() -> None:
    score, verdict = compute_risk([_f("bidi_control_char", Severity.HIGH)])
    # Score drives BLOCK on its own (30, cap 30). But override would also fire.
    assert verdict is Verdict.BLOCK


def test_hard_block_reverse_shell_with_zero_other_findings() -> None:
    # reverse_shell category alone: 25 score → REVIEW band — but override forces BLOCK.
    score, verdict = compute_risk([_f("reverse_shell", Severity.CRITICAL)])
    assert score == 25
    assert verdict is Verdict.BLOCK


def test_hard_block_crypto_miner_overrides() -> None:
    _, verdict = compute_risk([_f("crypto_miner", Severity.CRITICAL)])
    assert verdict is Verdict.BLOCK


def test_modelscan_critical_forces_block() -> None:
    f = _f("modelscan_high", Severity.CRITICAL)
    _, verdict = compute_risk([f])
    assert verdict is Verdict.BLOCK


def test_modelscan_high_alone_doesnt_force_block() -> None:
    # modelscan_high HIGH severity: 20 score → LOW_RISK band, no override.
    score, verdict = compute_risk([_f("modelscan_high", Severity.HIGH)])
    assert score == 20
    assert verdict is Verdict.LOW_RISK


def test_severity_passed_as_string_still_works() -> None:
    # Pydantic stores severity as a string when use_enum_values=True; the
    # scoring algorithm must tolerate either form.
    f = Finding(
        scanner="x",
        category="modelscan_high",
        severity="critical",  # type: ignore[arg-type]
        title="m",
        description="m",
    )
    _, verdict = compute_risk([f])
    assert verdict is Verdict.BLOCK


def test_annotate_findings_caps_contribution() -> None:
    # 5 cve_critical findings: per_finding=10, cap=30 → first 3 contribute 10 each;
    # remaining 2 contribute 0.
    findings = [_f("cve_critical", Severity.CRITICAL) for _ in range(5)]
    annotate_findings(findings)
    contribs = [f.score_contribution for f in findings]
    assert sum(contribs) == 30
    assert contribs[:3] == [10, 10, 10]
    assert contribs[3:] == [0, 0]


def test_annotate_findings_ignores_unknown_category() -> None:
    findings = [_f("nonexistent")]
    annotate_findings(findings)
    assert findings[0].score_contribution == 0


@pytest.mark.parametrize(
    "category,expected_verdict",
    [
        ("bidi_control_char", Verdict.BLOCK),
        ("reverse_shell", Verdict.BLOCK),
        ("crypto_miner", Verdict.BLOCK),
    ],
)
def test_each_hard_block_category(category: str, expected_verdict: Verdict) -> None:
    _, verdict = compute_risk([_f(category, Severity.CRITICAL)])
    assert verdict is expected_verdict
