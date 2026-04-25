"""Report writers: report.md, report.json, SKILL.md."""

from __future__ import annotations

import getpass
from datetime import datetime, timezone
from pathlib import Path

from ossvet.github_api import RepoMeta
from ossvet.models import Finding, ScanResult, Severity, Verdict

# Order in which categories appear in the report — and the section title for each.
_CATEGORY_SECTIONS: list[tuple[str, list[str]]] = [
    ("Provenance", [
        "single_contributor", "new_maintainer_account",
        "star_velocity_spike", "stale_repo",
    ]),
    ("Vulnerabilities (CVE)", ["cve_critical", "cve_high"]),
    ("Secrets", ["verified_secret", "unverified_secret"]),
    ("Static Analysis", ["semgrep_error", "semgrep_warning"]),
    ("Risky Files", [
        "npm_install_script", "setup_py_hook",
        "vscode_exec_config", "ci_workflow_risk",
    ]),
    ("Suspicious Patterns", [
        "curl_pipe_shell", "obfuscation", "credential_targeting",
        "reverse_shell", "time_bomb", "crypto_miner",
    ]),
    ("Unicode / Trojan Source", [
        "bidi_control_char", "zero_width_in_ident", "homoglyph",
    ]),
    ("ML Models", ["unsafe_model_format", "modelscan_high"]),
    ("Dependency Hygiene", ["typosquat_suspect", "unpinned_deps"]),
]


_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _sev(f: Finding) -> Severity:
    return f.severity if isinstance(f.severity, Severity) else Severity(f.severity)


def ensure_dirs(output_dir: Path) -> Path:
    """Create output_dir and output_dir/raw, return raw path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    raw = output_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    return raw


def write_json(scan: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(scan.model_dump_json(indent=2), encoding="utf-8")


def write_markdown(scan: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_markdown(scan), encoding="utf-8")


def write_skill_md(scan: ScanResult, meta: RepoMeta | None, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_skill(scan, meta), encoding="utf-8")


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _verdict_str(v: Verdict | str) -> str:
    return v.value if isinstance(v, Verdict) else str(v)


def _findings_by_category(findings: list[Finding], cats: list[str]) -> list[Finding]:
    result = [f for f in findings if f.category in cats]
    result.sort(key=lambda f: (-_SEVERITY_ORDER[_sev(f)], f.scanner, f.file_path or ""))
    return result


def _format_finding_line(f: Finding) -> str:
    loc = ""
    if f.file_path:
        loc = f" — `{f.file_path}`"
        if f.line_number:
            loc += f":{f.line_number}"
    sev = _sev(f).value.upper()
    return f"- **{sev}** — {f.title}{loc}"


def _render_markdown(scan: ScanResult) -> str:
    findings = list(scan.all_findings)
    findings.sort(key=lambda f: (-_SEVERITY_ORDER[_sev(f)], -f.score_contribution))
    top_findings = findings[:10]

    lines: list[str] = []
    lines.append("# OSS Vet Report")
    lines.append("")
    lines.append(f"**Repository:** {scan.repo_url}")
    lines.append(f"**Commit:** `{scan.commit_sha}`")
    lines.append(f"**Scanned:** {scan.timestamp.isoformat()}")
    lines.append(f"**Duration:** {scan.duration_seconds:.2f}s")
    lines.append("")
    lines.append(f"## Verdict: {_verdict_str(scan.verdict)}")
    lines.append(f"**Risk Score:** {scan.risk_score} / 100")
    lines.append("")

    lines.append("## Executive Summary")
    if scan.summary:
        for s in scan.summary:
            lines.append(f"- {s}")
    else:
        lines.append("- No notable findings.")
    lines.append("")

    lines.append("## Top Findings")
    if top_findings:
        for i, f in enumerate(top_findings, 1):
            lines.append(f"{i}. {_format_finding_line(f).removeprefix('- ')}")
    else:
        lines.append("_None._")
    lines.append("")

    lines.append("## Findings by Category")
    for section_title, cats in _CATEGORY_SECTIONS:
        section_findings = _findings_by_category(findings, cats)
        lines.append(f"### {section_title}")
        if not section_findings:
            lines.append("_No findings._")
        else:
            for f in section_findings:
                lines.append(_format_finding_line(f))
                if f.description and f.description != f.title:
                    lines.append(f"  - {f.description}")
        lines.append("")

    lines.append("## Scanner Status")
    lines.append("")
    lines.append("| Scanner | Status | Tool available | Duration | Findings | Notes |")
    lines.append("|---------|--------|----------------|----------|----------|-------|")
    for r in scan.scanner_results:
        notes = (r.error_message or "").replace("|", "/")
        lines.append(
            f"| {r.scanner_name} | {r.status} | {r.tool_available} | "
            f"{r.duration_seconds:.2f}s | {len(r.findings)} | {notes} |"
        )
    lines.append("")

    lines.append("## Recommended Next Actions")
    for rec in _recommendations(scan):
        lines.append(f"- {rec}")
    lines.append("")

    lines.append("## Raw Outputs")
    raw_paths = [r.raw_output_path for r in scan.scanner_results if r.raw_output_path]
    if raw_paths:
        for p in raw_paths:
            lines.append(f"- `{p}`")
    else:
        lines.append("_No raw outputs produced._")
    lines.append("")

    return "\n".join(lines)


def _recommendations(scan: ScanResult) -> list[str]:
    recs: list[str] = []
    cats = {f.category for f in scan.all_findings}
    if "bidi_control_char" in cats:
        recs.append("BIDI characters detected — review the file with a hex editor before reading the source.")
    if "reverse_shell" in cats:
        recs.append("Reverse-shell signature detected — do NOT run, install, or build this repo locally.")
    if "crypto_miner" in cats:
        recs.append("Cryptocurrency miner signatures detected — treat repo as malicious.")
    if "npm_install_script" in cats:
        recs.append("npm postinstall/preinstall scripts present — install with --ignore-scripts or in a sandbox.")
    if "setup_py_hook" in cats:
        recs.append("setup.py overrides install command — never `pip install` directly; build a wheel offline first.")
    if "verified_secret" in cats or "unverified_secret" in cats:
        recs.append("Secrets detected — rotate any leaked credentials immediately.")
    if "cve_critical" in cats:
        recs.append("Critical CVEs in declared dependencies — pin or replace them before adopting.")
    if "typosquat_suspect" in cats:
        recs.append("Possible typosquatted dependency — verify the package name matches an upstream you trust.")
    if not recs:
        recs.append("No critical issues. Standard code review still recommended before adopting.")
    return recs


# ---------------------------------------------------------------------------
# SKILL.md (PRD §8.3)
# ---------------------------------------------------------------------------

def _network_endpoints(findings: list[Finding]) -> list[str]:
    """Heuristic: pull URLs out of pattern findings' descriptions."""
    eps: set[str] = set()
    for f in findings:
        if f.scanner != "patterns":
            continue
        desc = f.description or ""
        for token in desc.split():
            if token.startswith(("http://", "https://", "tcp://")):
                eps.add(token.rstrip(",.;)\"'"))
    return sorted(eps)


def _filesystem_targets(findings: list[Finding]) -> list[str]:
    targets: set[str] = set()
    for f in findings:
        if f.category == "credential_targeting":
            targets.add(f.title)
    return sorted(targets)


def _render_skill(scan: ScanResult, meta: RepoMeta | None) -> str:
    cats = {f.category for f in scan.all_findings}
    install_hooks = bool(cats & {"npm_install_script", "setup_py_hook"})

    findings_list = list(scan.all_findings)
    static_n = sum(1 for f in findings_list if f.scanner in {"semgrep", "patterns", "risky_files"})
    cve_n = sum(1 for f in findings_list if f.category in {"cve_critical", "cve_high"})
    secret_n = sum(1 for f in findings_list if f.category in {"verified_secret", "unverified_secret"})
    unicode_n = sum(1 for f in findings_list if f.category in {
        "bidi_control_char", "zero_width_in_ident", "homoglyph",
    })
    model_n = sum(1 for f in findings_list if f.category in {"modelscan_high", "unsafe_model_format"})
    has_models = any(r.scanner_name == "modelscan" and r.status == "ok" for r in scan.scanner_results)

    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "unknown"

    now = datetime.now(timezone.utc).isoformat()
    license_line = meta.license_name if meta and meta.license_name else "_unknown_"
    last_active = meta.pushed_at if meta and meta.pushed_at else "_unknown_"
    owner_line = meta.owner_login if meta and meta.owner_login else "_unknown_"

    lines: list[str] = []
    lines.append("# SKILL.md — Auto-generated by ossvet")
    lines.append("")
    lines.append("## Identity")
    lines.append(f"- Source URL: {scan.repo_url}")
    lines.append(f"- Commit hash (pin this): `{scan.commit_sha}`")
    lines.append(f"- Author/org: {owner_line}")
    lines.append(f"- License: {license_line}")
    lines.append(f"- Last active commit: {last_active}")
    lines.append("")

    lines.append("## Vetting log")
    lines.append(f"- [x] Provenance: {_verdict_str(scan.verdict)}")
    lines.append(f"- [x] Static analysis: {static_n} findings")
    lines.append(f"- [x] Dependency audit: {cve_n} CVEs")
    lines.append(f"- [x] Secret scan: {secret_n} leaks")
    lines.append(f"- [x] Unicode trojan scan: {'flagged' if unicode_n else 'clean'}")
    if has_models:
        lines.append(f"- [x] ML model scan: {model_n} findings")
    else:
        lines.append("- [x] ML model scan: n/a")
    lines.append("- [ ] Sandboxed runtime test: pending (v0.2 feature)")
    lines.append(f"- Vetted by: {user}")
    lines.append(f"- Vetted on: {now}")
    lines.append("")

    lines.append("## Integration constraints")
    eps = _network_endpoints(findings_list)
    fs_targets = _filesystem_targets(findings_list)
    lines.append(f"- Declared network endpoints: {', '.join(eps) if eps else 'none observed in static scan'}")
    lines.append(f"- Declared filesystem access: {', '.join(fs_targets) if fs_targets else 'none observed in static scan'}")
    lines.append(f"- Install-time hooks present: {'yes' if install_hooks else 'no'}")
    lines.append("")

    lines.append("## Risk acceptance")
    lines.append("<!-- Filled in by a human before merge. -->")
    lines.append("")

    return "\n".join(lines)
