"""Scanner base class + shared utilities (subprocess wrapper, file walker).

Every subprocess invocation in ossvet must go through `safe_run_subprocess`.
The scanned repository is treated as fully untrusted, so we strictly enforce:
    * shell=False, list-form args
    * a hard timeout
    * ANSI escape stripping on captured output
    * the helper itself never raises
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from ossvet.config import (
    DEFAULT_TIMEOUT,
    MAX_SCAN_FILE_BYTES,
    SKIP_DIRS,
    TEXT_EXTENSIONS,
    TEXT_FILENAMES,
)
from ossvet.models import ScannerResult

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


@dataclass
class SubprocessResult:
    returncode: int
    stdout: str
    stderr: str
    error: str | None
    timed_out: bool


def safe_run_subprocess(
    args: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    cwd: str | os.PathLike[str] | None = None,
    env: dict[str, str] | None = None,
) -> SubprocessResult:
    """Run a subprocess safely. Never raises."""
    if not args:
        return SubprocessResult(-1, "", "", "empty args", False)

    try:
        proc = subprocess.run(  # noqa: S603 - shell=False, list args
            args,
            shell=False,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return SubprocessResult(
            returncode=-1,
            stdout=strip_ansi(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=strip_ansi(exc.stderr or "") if isinstance(exc.stderr, str) else "",
            error=f"timed out after {timeout}s",
            timed_out=True,
        )
    except FileNotFoundError as exc:
        return SubprocessResult(-1, "", "", f"executable not found: {exc.filename}", False)
    except OSError as exc:
        return SubprocessResult(-1, "", "", f"OSError: {exc}", False)
    except Exception as exc:  # noqa: BLE001 - we promise never to raise
        return SubprocessResult(-1, "", "", f"unexpected error: {exc!r}", False)

    return SubprocessResult(
        returncode=proc.returncode,
        stdout=strip_ansi(proc.stdout or ""),
        stderr=strip_ansi(proc.stderr or ""),
        error=None,
        timed_out=False,
    )


def tool_on_path(tool: str) -> bool:
    return shutil.which(tool) is not None


# ---------------------------------------------------------------------------
# Filesystem walker — shared by patterns / unicode_trojan / risky_files
# ---------------------------------------------------------------------------

def _is_text_file(path: Path) -> bool:
    if path.name in TEXT_FILENAMES:
        return True
    suffix = path.suffix.lower()
    if suffix in TEXT_EXTENSIONS:
        return True
    return False


def _looks_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return True
    return b"\x00" in chunk


def iter_text_files(repo_path: Path) -> Iterator[Path]:
    """Yield text files under `repo_path` that are safe to scan.

    Skips: .git/, node_modules/, build dirs; symlinks; binary files;
    files larger than MAX_SCAN_FILE_BYTES.
    """
    repo_root = repo_path.resolve()
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            full = Path(dirpath) / fname
            try:
                if full.is_symlink():
                    continue
                resolved = full.resolve()
                if not str(resolved).startswith(str(repo_root)):
                    continue  # symlink escape
                if not _is_text_file(full):
                    continue
                size = full.stat().st_size
                if size > MAX_SCAN_FILE_BYTES:
                    continue
                if size > 0 and _looks_binary(full):
                    continue
            except OSError:
                continue
            yield full


def read_text_safely(path: Path) -> str | None:
    """Read a file as UTF-8 text. Returns None on any error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Scanner ABC
# ---------------------------------------------------------------------------

class BaseScanner(ABC):
    """Every scanner must subclass this and override `name`/`required_tool`."""

    name: str = ""
    required_tool: str | None = None  # CLI executable name; None if pure-Python

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    def is_available(self) -> bool:
        if self.required_tool is None:
            return True
        return tool_on_path(self.required_tool)

    @abstractmethod
    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        """Run the scan. MUST return a ScannerResult — never raise."""

    # ---------- helpers used by subclasses ------------------------------

    def _skipped(self, reason: str) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.name,
            status="skipped",
            tool_available=self.is_available(),
            error_message=reason,
        )

    def _error(self, reason: str, *, duration: float = 0.0) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.name,
            status="error",
            tool_available=self.is_available(),
            error_message=reason,
            duration_seconds=duration,
        )

    def _ok(
        self,
        findings: list,  # type: ignore[type-arg]
        duration: float,
        raw_output_path: str | None = None,
    ) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.name,
            status="ok",
            tool_available=self.is_available(),
            findings=findings,
            duration_seconds=duration,
            raw_output_path=raw_output_path,
        )

    # convenience timing context for subclasses
    def _now(self) -> float:
        return time.perf_counter()
