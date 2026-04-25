"""Typer entrypoint for ossvet.

Subcommands:
    scan     — clone + scan a GitHub repo + write reports
    doctor   — show which underlying scanners are installed
    version  — print version info

Exit codes:
    0 — scan completed; verdict below --fail-on threshold
    1 — scan completed; verdict at or above --fail-on threshold
    2 — scan could not complete (clone failed, invalid URL, etc.)
    3 — internal error
"""

from __future__ import annotations

import os
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

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

_PURE_PYTHON_SCANNERS = {
    "risky_files", "patterns", "unicode_trojan",
    "dependency_hygiene", "provenance",
}


# ---------------------------------------------------------------------------
# Scanner registry
# ---------------------------------------------------------------------------

def get_scanners(timeout: int = DEFAULT_TIMEOUT) -> list[BaseScanner]:
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
        RiskyFilesScanner(timeout=timeout),
        PatternsScanner(timeout=timeout),
        UnicodeTrojanScanner(timeout=timeout),
        DependencyHygieneScanner(timeout=timeout),
        ProvenanceScanner(timeout=timeout),
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
    "low":   Verdict.LOW_RISK,
    "review": Verdict.REVIEW,
    "block": Verdict.BLOCK,
    "never": None,
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
    sev_rank = {
        Severity.CRITICAL: 4, Severity.HIGH: 3,
        Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0,
    }

    def sev_of(f: Finding) -> Severity:
        return f.severity if isinstance(f.severity, Severity) else Severity(f.severity)

    ranked = sorted(findings, key=lambda f: (-sev_rank[sev_of(f)], -f.score_contribution))
    return [f.title for f in ranked[:top_n]]


def _verdict_style(v: Verdict) -> str:
    if v is Verdict.BLOCK:
        return "bold red"
    if v is Verdict.REVIEW:
        return "bold yellow"
    return "bold green"


def _to_verdict(v: Verdict | str) -> Verdict:
    return v if isinstance(v, Verdict) else Verdict(v)


def _verdict_str(v: Verdict | str) -> str:
    return _to_verdict(v).value


def _print_verdict_panel(scan: ScanResult) -> None:
    sev_style = _verdict_style(_to_verdict(scan.verdict))
    body_lines = [
        f"[bold]Repo:[/bold]      {scan.repo_url}",
        f"[bold]Commit:[/bold]    {scan.commit_sha[:12]}",
        f"[bold]Verdict:[/bold]   [{sev_style}]{_verdict_str(scan.verdict)}[/]",
        f"[bold]Score:[/bold]     {scan.risk_score} / 100",
        f"[bold]Duration:[/bold]  {scan.duration_seconds:.1f}s",
        "",
        "[bold]Top Findings:[/bold]",
    ]
    if scan.summary:
        for i, s in enumerate(scan.summary, 1):
            body_lines.append(f"  {i}. {s}")
    else:
        body_lines.append("  (none)")
    console.print(Panel("\n".join(body_lines), title="OSS Vet Report", border_style=sev_style))


# ---------------------------------------------------------------------------
# Live scanner progress display
# ---------------------------------------------------------------------------

_STATUS_ICONS = {
    "running": "[cyan]⟳[/cyan]",
    "ok":      "[green]✓[/green]",
    "skipped": "[dim]–[/dim]",
    "error":   "[red]✗[/red]",
    "pending": "[dim]·[/dim]",
}


def _build_progress_table(
    scanners: list[BaseScanner],
    statuses: dict[str, tuple[str, str, int, float]],  # name → (status, note, n_findings, duration)
) -> Table:
    t = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
    t.add_column("", width=2)
    t.add_column("Scanner", style="cyan", no_wrap=True)
    t.add_column("Findings", justify="right")
    t.add_column("Duration", justify="right")
    t.add_column("Note", style="dim")
    for s in scanners:
        icon, note, n_findings, dur = statuses.get(
            s.name, ("pending", "", 0, 0.0)
        )
        icon_str = _STATUS_ICONS.get(icon, "·")
        dur_str = f"{dur:.1f}s" if dur > 0 else ""
        n_str = str(n_findings) if icon == "ok" else ""
        t.add_row(icon_str, s.name, n_str, dur_str, note)
    return t


def _run_scanners_live(
    scanners: list[BaseScanner],
    repo_path: Path,
    raw_dir: Path,
    *,
    repo_url: str,
    repo_meta: RepoMeta | None,
    use_api: bool,
) -> list[ScannerResult]:
    """Dispatch scanners in a thread pool; update a Live table as each finishes."""
    statuses: dict[str, tuple[str, str, int, float]] = {
        s.name: ("pending", "", 0, 0.0) for s in scanners
    }
    results: list[ScannerResult] = []
    start_times: dict[str, float] = {}

    def _invoke(scanner: BaseScanner) -> ScannerResult:
        start_times[scanner.name] = time.perf_counter()
        statuses[scanner.name] = ("running", "", 0, 0.0)
        kwargs: dict[str, object] = {
            "raw_dir": raw_dir,
            "repo_url": repo_url,
            "repo_meta": repo_meta,
            "use_api": use_api,
        }
        try:
            result = scanner.run(repo_path, **kwargs)
        except Exception as exc:  # noqa: BLE001
            result = ScannerResult(
                scanner_name=scanner.name or scanner.__class__.__name__,
                status="error",
                tool_available=scanner.is_available(),
                error_message=f"unhandled exception: {exc!r}",
            )
        dur = time.perf_counter() - start_times[scanner.name]
        note = (result.error_message or "")[:60] if result.status in ("error", "skipped") else ""
        statuses[scanner.name] = (result.status, note, len(result.findings), dur)
        return result

    with ThreadPoolExecutor(max_workers=min(8, max(1, len(scanners)))) as pool:
        future_to_scanner: dict[Future[ScannerResult], BaseScanner] = {
            pool.submit(_invoke, s): s for s in scanners
        }
        with Live(
            _build_progress_table(scanners, statuses),
            console=console,
            refresh_per_second=8,
            transient=False,
        ) as live:
            for fut in _future_as_completed(future_to_scanner):
                results.append(fut.result())
                live.update(_build_progress_table(scanners, statuses))

    results.sort(key=lambda r: r.scanner_name)
    return results


def _future_as_completed(
    future_map: dict[Future[ScannerResult], BaseScanner],
) -> list[Future[ScannerResult]]:
    from concurrent.futures import as_completed
    return list(as_completed(future_map))


# ---------------------------------------------------------------------------
# Scan pipeline — exposed for tests via _scan_path
# ---------------------------------------------------------------------------

def _filter_scanners(
    all_scanners: list[BaseScanner],
    skip: list[str],
    only: list[str],
    deep: bool = False,
) -> list[BaseScanner]:
    if only:
        wanted = {s.lower() for s in only}
        return [s for s in all_scanners if s.name.lower() in wanted]
    candidates = all_scanners if deep else [s for s in all_scanners if s.name in _PURE_PYTHON_SCANNERS]
    if skip:
        unwanted = {s.lower() for s in skip}
        candidates = [s for s in candidates if s.name.lower() not in unwanted]
    return candidates


def _scan_path(
    repo_path: Path,
    *,
    repo_url: str,
    commit_sha: str,
    output_dir: Path,
    timeout: int = DEFAULT_TIMEOUT,
    skip: list[str] | None = None,
    only: list[str] | None = None,
    deep: bool = False,
    use_api: bool = True,
    repo_meta: RepoMeta | None = None,
    live: bool = False,
) -> ScanResult:
    """Run the scan pipeline against an already-cloned repo_path. Exposed for tests."""
    raw_dir = ensure_dirs(output_dir)
    scanners = _filter_scanners(get_scanners(timeout=timeout), skip or [], only or [], deep=deep)

    started = time.perf_counter()
    if live:
        scanner_results = _run_scanners_live(
            scanners, repo_path, raw_dir,
            repo_url=repo_url, repo_meta=repo_meta, use_api=use_api,
        )
    else:
        scanner_results = _run_scanners_silent(
            scanners, repo_path, raw_dir,
            repo_url=repo_url, repo_meta=repo_meta, use_api=use_api,
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


def _run_scanners_silent(
    scanners: list[BaseScanner],
    repo_path: Path,
    raw_dir: Path,
    *,
    repo_url: str,
    repo_meta: RepoMeta | None,
    use_api: bool,
) -> list[ScannerResult]:
    """No live display — used by tests."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results: list[ScannerResult] = []

    def _invoke(scanner: BaseScanner) -> ScannerResult:
        kwargs: dict[str, object] = {
            "raw_dir": raw_dir, "repo_url": repo_url,
            "repo_meta": repo_meta, "use_api": use_api,
        }
        try:
            return scanner.run(repo_path, **kwargs)
        except Exception as exc:  # noqa: BLE001
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

    results.sort(key=lambda r: r.scanner_name)
    return results


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def scan(
    repo_url: Annotated[str, typer.Argument(help="GitHub repo URL to vet")],
    deep: Annotated[bool, typer.Option("--deep", help="Also run external scanners (semgrep, grype, gitleaks…). Slower but more thorough.")] = False,
    output_dir: Annotated[Path, typer.Option(help="Where to write reports")] = Path("reports"),
    keep_clone: Annotated[bool, typer.Option(help="Retain the temp clone after scan")] = False,
    timeout: Annotated[int, typer.Option(help="Per-scanner subprocess timeout (seconds)")] = DEFAULT_TIMEOUT,
    skip: Annotated[list[str], typer.Option(help="Scanner names to skip (repeatable)")] = [],
    only: Annotated[list[str], typer.Option(help="Run only these scanners (repeatable)")] = [],
    fail_on: Annotated[str, typer.Option(help="Exit non-zero if verdict >= this: low/review/block/never")] = "block",
    no_api: Annotated[bool, typer.Option(help="Skip GitHub API calls (provenance + scorecard)")] = False,
) -> None:
    """Vet a GitHub repo and produce a trust report.

    By default runs the fast pure-Python scanners (~5s). Add --deep to also
    invoke semgrep, grype, syft, gitleaks, scorecard, and modelscan.
    """
    _refuse_root()

    if fail_on not in _FAIL_ON_TO_VERDICT:
        console.print(f"[red]--fail-on={fail_on!r} is invalid. Choose: low / review / block / never[/red]")
        raise typer.Exit(code=3)

    try:
        validate_repo_url(repo_url)
    except GitHubError as exc:
        console.print(f"[red]Invalid GitHub URL:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    mode_label = "[bold]deep[/bold] (all scanners)" if deep else "[bold]fast[/bold] (pure-Python)"
    console.print(f"\n[bold cyan]ossvet[/bold cyan] {__version__}  •  mode: {mode_label}\n")

    repo_meta: RepoMeta | None = None
    if not no_api:
        with console.status("[cyan]Checking GitHub API…[/cyan]", spinner="dots"):
            try:
                owner, name = validate_repo_url(repo_url)
                with httpx.Client(headers={"Accept": "application/vnd.github+json"}) as client:
                    repo_meta = get_repo_meta(owner, name, client=client)
                console.print(f"[green]✓[/green] GitHub API — repo confirmed, size {repo_meta.size_kb // 1024} MB")
            except GitHubError as exc:
                console.print(f"[yellow]![/yellow] GitHub API skipped: {exc}")

    with console.status("[cyan]Cloning…[/cyan]", spinner="dots"):
        try:
            clone_ctx = clone_repo(repo_url, keep=keep_clone)
            info = clone_ctx.__enter__()
        except CloneError as exc:
            console.print(f"[red]Clone failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc

    console.print(f"[green]✓[/green] Cloned @ [bold]{info.commit_sha[:12]}[/bold]\n")

    try:
        scan_result = _scan_path(
            info.path,
            repo_url=repo_url,
            commit_sha=info.commit_sha,
            output_dir=output_dir,
            timeout=timeout,
            skip=skip,
            only=only,
            deep=deep,
            use_api=not no_api,
            repo_meta=repo_meta,
            live=True,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Internal error:[/red] {exc!r}")
        clone_ctx.__exit__(None, None, None)
        raise typer.Exit(code=3) from exc
    finally:
        clone_ctx.__exit__(None, None, None)

    console.print()
    _print_verdict_panel(scan_result)

    console.print(f"\n[dim]Reports →[/dim] [bold]{output_dir.resolve()}[/bold]")
    for fname in ("report.md", "report.json", "SKILL.md"):
        console.print(f"  [dim]•[/dim] {output_dir / fname}")

    if not deep:
        console.print(
            "\n[dim]Tip: run with [bold]--deep[/bold] to also invoke semgrep, grype, gitleaks, "
            "and scorecard for a more thorough scan.[/dim]"
        )

    if _fail_threshold_met(_to_verdict(scan_result.verdict), fail_on):
        raise typer.Exit(code=1)


@app.command()
def doctor(
    fix: Annotated[bool, typer.Option("--fix", help="Auto-install missing tools (macOS/Homebrew + pip)")] = False,
) -> None:
    """Show which underlying scanners are installed. Use --fix to install missing ones."""
    scanners = get_scanners()
    missing = [s for s in scanners if s.required_tool and not s.is_available()]

    table = Table(title="ossvet scanner status", box=None, padding=(0, 1))
    table.add_column("", width=2)
    table.add_column("Scanner")
    table.add_column("Tool")
    table.add_column("Status", justify="center")
    table.add_column("Install command")

    for s in scanners:
        tool = s.required_tool or "(pure-Python)"
        avail = s.is_available()
        icon = "[green]✓[/green]" if avail else "[red]✗[/red]"
        hint = ""
        if s.required_tool and not avail:
            hint = INSTALL_HINTS.get(s.required_tool, "see project docs")
        status_str = "[green]ok[/green]" if avail else "[red]missing[/red]"
        table.add_row(icon, s.name, tool, status_str, hint)

    console.print(table)

    if missing and not fix:
        console.print(
            f"\n[yellow]{len(missing)} scanner(s) missing.[/yellow] "
            "Run [bold]ossvet doctor --fix[/bold] to install them automatically (macOS/Homebrew)."
        )
        return

    if not missing:
        console.print("\n[green]All scanners available.[/green]")
        return

    if fix:
        _auto_install(missing)


def _auto_install(missing: list[BaseScanner]) -> None:
    """Attempt to install missing tools via Homebrew + pip (macOS)."""
    import shutil
    import subprocess

    brew_tools = {
        "semgrep":   ["brew", "install", "semgrep"],
        "syft":      ["brew", "install", "syft"],
        "grype":     ["brew", "install", "grype"],
        "gitleaks":  ["brew", "install", "gitleaks"],
        "scorecard": ["brew", "install", "ossf/scorecard/scorecard"],
    }
    pip_tools = {
        "modelscan": [sys.executable, "-m", "pip", "install", "modelscan"],
    }

    has_brew = shutil.which("brew") is not None

    for s in missing:
        tool = s.required_tool or ""
        console.print(f"\n[cyan]Installing {tool}…[/cyan]")
        cmd: list[str] | None = None
        if tool in brew_tools:
            if not has_brew:
                console.print(f"  [yellow]Homebrew not found. Install manually:[/yellow] {INSTALL_HINTS.get(tool, '')}")
                continue
            cmd = brew_tools[tool]
        elif tool in pip_tools:
            cmd = pip_tools[tool]
        else:
            console.print(f"  [yellow]No auto-install recipe for {tool}. Install manually.[/yellow]")
            continue

        result = subprocess.run(cmd, shell=False, capture_output=False)  # noqa: S603
        if result.returncode == 0:
            console.print(f"  [green]✓ {tool} installed.[/green]")
        else:
            console.print(f"  [red]✗ {tool} install failed (exit {result.returncode}).[/red]")

    console.print("\n[cyan]Re-running doctor…[/cyan]")
    doctor()


@app.command()
def version() -> None:
    """Print version info."""
    console.print(f"ossvet {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
