"""Typer entrypoint for ossvet.

Subcommands:
    scan     — clone + scan a GitHub repo + write reports
    doctor   — show which underlying scanners are installed
    version  — print version info

Exit codes (PRD §9):
    0 — scan completed; verdict below --fail-on threshold
    1 — scan completed; verdict at or above --fail-on threshold
    2 — scan could not complete (clone failed, invalid URL, etc.)
    3 — internal error
"""

from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ossvet import __version__
from ossvet.clone import CloneError, clone_repo
from ossvet.config import DEFAULT_TIMEOUT, INSTALL_HINTS
from ossvet.github_api import GitHubError, RepoMeta, get_repo_meta, validate_repo_url
from ossvet.models import Finding, ScanResult, ScannerResult, Severity, Verdict
from ossvet.reporting import ensure_dirs, write_json, write_markdown, write_skill_md
from ossvet.scanners.base import BaseScanner
from ossvet.scoring import annotate_findings, compute_risk

app = typer.Typer(
    add_completion=False,
    help="OSS Vet — decide whether an OSS repo is safe to run.",
    no_args_is_help=True,
)

console = Console()


# ---------------------------------------------------------------------------
# Scanner registry — populated by import-time discovery.
# ---------------------------------------------------------------------------

def get_scanners(timeout: int = DEFAULT_TIMEOUT) -> list[BaseScanner]:
    """Return one instance of every registered scanner."""
    # Local imports so a partial install / missing optional dep on one
    # scanner can't take the rest down.
    from ossvet.scanners.dependency_hygiene import DependencyHygieneScanner
    from ossvet.scanners.gitleaks import GitleaksScanner
    from ossvet.scanners.grype import GrypeScanner
    from ossvet.scanners.modelscan import ModelScanScanner
    from ossvet.scanners.patterns import PatternsScanner
    from ossvet.scanners.provenance import ProvenanceScanner
    from ossvet.scanners.risky_files import RiskyFilesScanner
    from ossvet.scanners.scorecard import ScorecardScanner
    from ossvet.scanners.semgrep import SemgrepScanner
    from ossvet.scanners.syft import SyftScanner
    from ossvet.scanners.unicode_trojan import UnicodeTrojanScanner

    return [
        # Pure-Python first
        RiskyFilesScanner(timeout=timeout),
        PatternsScanner(timeout=timeout),
        UnicodeTrojanScanner(timeout=timeout),
        DependencyHygieneScanner(timeout=timeout),
        ProvenanceScanner(timeout=timeout),
        # External
        ScorecardScanner(timeout=timeout),
        SemgrepScanner(timeout=timeout),
        SyftScanner(timeout=timeout),
        GrypeScanner(timeout=timeout),
        GitleaksScanner(timeout=timeout),
        ModelScanScanner(timeout=timeout),
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _refuse_root() -> None:
    if sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0:
        console.print("[red]Refusing to run as root.[/red] Re-run as a non-privileged user.")
        raise typer.Exit(code=3)


_FAIL_ON_TO_VERDICT = {
    "low":    Verdict.LOW_RISK,
    "review": Verdict.REVIEW,
    "block":  Verdict.BLOCK,
    "never":  None,
}


def _fail_threshold_met(verdict: Verdict, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = _FAIL_ON_TO_VERDICT.get(fail_on)
    if threshold is None:
        return False
    order = [Verdict.LOW_RISK, Verdict.REVIEW, Verdict.BLOCK]
    return order.index(verdict) >= order.index(threshold)


def _build_summary(findings: list[Finding], top_n: int = 4) -> list[str]:
    """Top N findings as terse human-readable bullets."""
    sev_rank = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }

    def sev_of(f: Finding) -> Severity:
        return f.severity if isinstance(f.severity, Severity) else Severity(f.severity)

    ranked = sorted(
        findings,
        key=lambda f: (-sev_rank[sev_of(f)], -f.score_contribution),
    )
    return [f.title for f in ranked[:top_n]]


def _verdict_style(v: Verdict) -> str:
    if v is Verdict.BLOCK:
        return "bold red"
    if v is Verdict.REVIEW:
        return "bold yellow"
    return "bold green"


def _print_verdict_panel(scan: ScanResult) -> None:
    sev_style = _verdict_style(_to_verdict(scan.verdict))
    body_lines = [
        f"[bold]Repo:[/bold]      {scan.repo_url}",
        f"[bold]Commit:[/bold]    {scan.commit_sha}",
        f"[bold]Verdict:[/bold]   [{sev_style}]{_verdict_str(scan.verdict)}[/]",
        f"[bold]Score:[/bold]     {scan.risk_score} / 100",
        "",
        "[bold]Top Findings:[/bold]",
    ]
    if scan.summary:
        for i, s in enumerate(scan.summary, 1):
            body_lines.append(f"  {i}. {s}")
    else:
        body_lines.append("  _none_")
    console.print(Panel("\n".join(body_lines), title="OSS Vet Report", border_style=sev_style))


def _to_verdict(v: Verdict | str) -> Verdict:
    if isinstance(v, Verdict):
        return v
    return Verdict(v)


def _verdict_str(v: Verdict | str) -> str:
    return _to_verdict(v).value


# ---------------------------------------------------------------------------
# Scan pipeline (also reused by the e2e tests via _scan_path)
# ---------------------------------------------------------------------------

def _run_scanners(
    scanners: list[BaseScanner],
    repo_path: Path,
    raw_dir: Path,
    *,
    repo_url: str,
    repo_meta: RepoMeta | None,
    use_api: bool,
) -> list[ScannerResult]:
    """Dispatch all scanners in a thread pool and return their results."""
    results: list[ScannerResult] = []

    def _invoke(scanner: BaseScanner) -> ScannerResult:
        kwargs: dict[str, object] = {
            "raw_dir": raw_dir,
            "repo_url": repo_url,
            "repo_meta": repo_meta,
            "use_api": use_api,
        }
        try:
            return scanner.run(repo_path, **kwargs)
        except Exception as exc:  # noqa: BLE001 - scanners must never raise, but defend
            return ScannerResult(
                scanner_name=scanner.name or scanner.__class__.__name__,
                status="error",
                tool_available=scanner.is_available(),
                error_message=f"unhandled scanner exception: {exc!r}",
            )

    with ThreadPoolExecutor(max_workers=min(8, max(1, len(scanners)))) as pool:
        futures = {pool.submit(_invoke, s): s for s in scanners}
        for fut in as_completed(futures):
            results.append(fut.result())

    # Sort to ensure deterministic ordering by scanner name.
    results.sort(key=lambda r: r.scanner_name)
    return results


def _filter_scanners(
    all_scanners: list[BaseScanner],
    skip: list[str],
    only: list[str],
) -> list[BaseScanner]:
    if only:
        wanted = {s.lower() for s in only}
        return [s for s in all_scanners if s.name.lower() in wanted]
    if skip:
        unwanted = {s.lower() for s in skip}
        return [s for s in all_scanners if s.name.lower() not in unwanted]
    return all_scanners


def _scan_path(
    repo_path: Path,
    *,
    repo_url: str,
    commit_sha: str,
    output_dir: Path,
    timeout: int = DEFAULT_TIMEOUT,
    skip: list[str] | None = None,
    only: list[str] | None = None,
    use_api: bool = True,
    repo_meta: RepoMeta | None = None,
) -> ScanResult:
    """Run the scan pipeline against an already-cloned `repo_path`.

    Exposed for tests.
    """
    raw_dir = ensure_dirs(output_dir)
    scanners = _filter_scanners(get_scanners(timeout=timeout), skip or [], only or [])

    started = time.perf_counter()
    scanner_results = _run_scanners(
        scanners,
        repo_path,
        raw_dir,
        repo_url=repo_url,
        repo_meta=repo_meta,
        use_api=use_api,
    )
    duration = time.perf_counter() - started

    all_findings: list[Finding] = []
    for r in scanner_results:
        all_findings.extend(r.findings)

    annotate_findings(all_findings)
    score, verdict = compute_risk(all_findings)

    scan = ScanResult(
        repo_url=repo_url,  # type: ignore[arg-type]
        commit_sha=commit_sha,
        timestamp=datetime.now(timezone.utc),
        duration_seconds=duration,
        scanner_results=scanner_results,
        all_findings=all_findings,
        risk_score=score,
        verdict=verdict,
        summary=_build_summary(all_findings),
    )

    write_json(scan, output_dir / "report.json")
    write_markdown(scan, output_dir / "report.md")
    write_skill_md(scan, repo_meta, output_dir / "SKILL.md")
    return scan


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def scan(
    repo_url: Annotated[str, typer.Argument(help="GitHub repo URL")],
    output_dir: Annotated[Path, typer.Option(help="Where to write reports")] = Path("reports"),
    keep_clone: Annotated[bool, typer.Option(help="Retain the temp clone after scan")] = False,
    timeout: Annotated[int, typer.Option(help="Per-scanner timeout in seconds")] = DEFAULT_TIMEOUT,
    skip: Annotated[list[str], typer.Option(help="Scanner names to skip")] = [],
    only: Annotated[list[str], typer.Option(help="Run only these scanners")] = [],
    fail_on: Annotated[str, typer.Option(help="Exit non-zero if verdict >= this (low/review/block/never)")] = "block",
    no_api: Annotated[bool, typer.Option(help="Skip GitHub API provenance checks")] = False,
) -> None:
    """Scan a GitHub repo and produce a trust report."""
    _refuse_root()

    if fail_on not in _FAIL_ON_TO_VERDICT:
        console.print(f"[red]invalid --fail-on={fail_on!r}; expected low/review/block/never[/red]")
        raise typer.Exit(code=3)

    try:
        validate_repo_url(repo_url)
    except GitHubError as exc:
        console.print(f"[red]Invalid GitHub URL:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    repo_meta: RepoMeta | None = None
    if not no_api:
        try:
            owner, name = validate_repo_url(repo_url)
            with httpx.Client(headers={"Accept": "application/vnd.github+json"}) as client:
                repo_meta = get_repo_meta(owner, name, client=client)
        except GitHubError as exc:
            console.print(f"[yellow]GitHub API check failed: {exc}[/yellow] (continuing without provenance)")
            repo_meta = None

    console.print(f"[cyan]Cloning[/cyan] {repo_url} ...")
    try:
        with clone_repo(repo_url, keep=keep_clone) as info:
            console.print(f"[cyan]Cloned[/cyan] {info.path} @ {info.commit_sha[:12]}")
            scan_result = _scan_path(
                info.path,
                repo_url=repo_url,
                commit_sha=info.commit_sha,
                output_dir=output_dir,
                timeout=timeout,
                skip=skip,
                only=only,
                use_api=not no_api,
                repo_meta=repo_meta,
            )
    except CloneError as exc:
        console.print(f"[red]Clone failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # noqa: BLE001 - top-level catch-all
        console.print(f"[red]Internal error:[/red] {exc!r}")
        raise typer.Exit(code=3) from exc

    _print_verdict_panel(scan_result)
    console.print(f"\nReports saved to [bold]{output_dir.resolve()}[/bold]:")
    for fname in ("report.md", "report.json", "SKILL.md"):
        console.print(f"  - {output_dir / fname}")

    verdict_obj = _to_verdict(scan_result.verdict)
    if _fail_threshold_met(verdict_obj, fail_on):
        raise typer.Exit(code=1)


@app.command()
def doctor() -> None:
    """Check which underlying scanners are installed and reachable."""
    table = Table(title="ossvet scanner status")
    table.add_column("Scanner")
    table.add_column("Tool")
    table.add_column("Available", justify="center")
    table.add_column("Install hint")

    for s in get_scanners():
        tool = s.required_tool or "(pure-Python)"
        avail = s.is_available()
        avail_str = "[green]yes[/green]" if avail else "[red]no[/red]"
        hint = ""
        if s.required_tool and not avail:
            hint = INSTALL_HINTS.get(s.required_tool, "see project docs")
        table.add_row(s.name, tool, avail_str, hint)

    console.print(table)


@app.command()
def version() -> None:
    """Print version info."""
    console.print(f"ossvet {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
