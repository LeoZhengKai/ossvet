"""Safe shallow clone of a GitHub repo into a temp directory."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ossvet.github_api import GitHubError, validate_repo_url
from ossvet.scanners.base import safe_run_subprocess


class CloneError(Exception):
    """Any failure during cloning."""


@dataclass
class CloneInfo:
    path: Path
    commit_sha: str


@contextmanager
def clone_repo(
    url: str,
    *,
    keep: bool = False,
    timeout: int = 120,
) -> Iterator[CloneInfo]:
    """Shallow-clone `url` into a fresh temp dir; yield a CloneInfo.

    Cleans up the temp dir on exit unless `keep=True`.

    Validates the URL with our strict regex before invoking git, so a hostile
    URL cannot smuggle git options or path traversal.
    """
    try:
        validate_repo_url(url)
    except GitHubError as exc:
        raise CloneError(str(exc)) from exc

    tmp_dir = Path(tempfile.mkdtemp(prefix="ossvet-"))
    target = tmp_dir / "repo"
    try:
        result = safe_run_subprocess(
            [
                "git",
                "clone",
                "--depth=1",
                "--no-tags",
                "--single-branch",
                "--",
                url,
                str(target),
            ],
            timeout=timeout,
        )
        if result.error:
            raise CloneError(f"git clone failed: {result.error}")
        if result.returncode != 0:
            raise CloneError(
                f"git clone exited {result.returncode}: {result.stderr.strip() or result.stdout.strip()}"
            )

        sha_result = safe_run_subprocess(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            timeout=10,
        )
        if sha_result.returncode != 0:
            raise CloneError(
                f"git rev-parse failed: {sha_result.stderr.strip() or 'unknown error'}"
            )
        commit_sha = sha_result.stdout.strip()
        if not commit_sha:
            raise CloneError("could not read commit SHA from clone")

        yield CloneInfo(path=target, commit_sha=commit_sha)
    finally:
        if not keep:
            shutil.rmtree(tmp_dir, ignore_errors=True)
