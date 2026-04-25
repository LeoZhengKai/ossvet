"""GitHub REST API helpers for URL validation and provenance metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from ossvet.config import GITHUB_API_TIMEOUT, MAX_REPO_SIZE_KB

# Strict GitHub URL regex. Owner/repo follow GitHub's character constraints:
# alphanumerics, dot, dash, underscore. Trailing .git and slash optional.
GITHUB_URL_RE = re.compile(
    r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$"
)


class GitHubError(Exception):
    """Any failure during GitHub API access."""


def validate_repo_url(url: str) -> tuple[str, str]:
    """Return (owner, name) or raise GitHubError on invalid URL.

    Defence-in-depth: caller must NOT hand the URL to git/scorecard/etc.
    until this passes.
    """
    if not isinstance(url, str):
        raise GitHubError("URL must be a string")
    match = GITHUB_URL_RE.match(url.strip())
    if not match:
        raise GitHubError(f"Not a valid https://github.com/<owner>/<repo> URL: {url!r}")
    owner, name = match.group(1), match.group(2)
    if owner in {".", ".."} or name in {".", ".."}:
        raise GitHubError("URL contains a relative path component")
    return owner, name


@dataclass
class RepoMeta:
    owner: str
    name: str
    default_branch: str = "main"
    created_at: str | None = None
    pushed_at: str | None = None
    stargazers_count: int = 0
    forks_count: int = 0
    size_kb: int = 0
    is_fork: bool = False
    parent_full_name: str | None = None
    archived: bool = False
    disabled: bool = False
    license_name: str | None = None
    owner_login: str | None = None
    owner_created_at: str | None = None
    contributor_count_at_least: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def _get_json(client: httpx.Client, url: str) -> Any:
    resp = client.get(url, timeout=GITHUB_API_TIMEOUT)
    if resp.status_code == 404:
        raise GitHubError(f"GitHub API 404: {url}")
    if resp.status_code == 403:
        raise GitHubError("GitHub API rate limit hit (try again later or set GITHUB_TOKEN)")
    if resp.status_code >= 400:
        raise GitHubError(f"GitHub API {resp.status_code}: {url}")
    return resp.json()


def get_repo_meta(owner: str, name: str, *, client: httpx.Client | None = None) -> RepoMeta:
    """Fetch repo + owner metadata. Raises GitHubError on failure."""
    own = client is None
    if own:
        client = httpx.Client(headers={"Accept": "application/vnd.github+json"})
    assert client is not None
    try:
        repo_data = _get_json(client, f"https://api.github.com/repos/{owner}/{name}")
        if not isinstance(repo_data, dict):
            raise GitHubError("Unexpected /repos/ response shape")

        size_kb = int(repo_data.get("size") or 0)
        if size_kb > MAX_REPO_SIZE_KB:
            raise GitHubError(
                f"Repo size {size_kb} KB exceeds limit {MAX_REPO_SIZE_KB} KB"
            )

        owner_obj = repo_data.get("owner") or {}
        owner_login = owner_obj.get("login")
        owner_created_at = None
        if owner_login:
            try:
                user_data = _get_json(client, f"https://api.github.com/users/{owner_login}")
                if isinstance(user_data, dict):
                    owner_created_at = user_data.get("created_at")
            except GitHubError:
                # Owner lookup is best-effort.
                owner_created_at = None

        contributor_count = 0
        try:
            contribs = _get_json(
                client,
                f"https://api.github.com/repos/{owner}/{name}/contributors?per_page=2&anon=true",
            )
            if isinstance(contribs, list):
                contributor_count = len(contribs)
        except GitHubError:
            contributor_count = 0

        license_obj = repo_data.get("license") or {}
        parent = repo_data.get("parent") or {}

        return RepoMeta(
            owner=owner,
            name=name,
            default_branch=repo_data.get("default_branch") or "main",
            created_at=repo_data.get("created_at"),
            pushed_at=repo_data.get("pushed_at"),
            stargazers_count=int(repo_data.get("stargazers_count") or 0),
            forks_count=int(repo_data.get("forks_count") or 0),
            size_kb=size_kb,
            is_fork=bool(repo_data.get("fork")),
            parent_full_name=parent.get("full_name"),
            archived=bool(repo_data.get("archived")),
            disabled=bool(repo_data.get("disabled")),
            license_name=license_obj.get("spdx_id") or license_obj.get("name"),
            owner_login=owner_login,
            owner_created_at=owner_created_at,
            contributor_count_at_least=contributor_count,
            raw=repo_data,
        )
    finally:
        if own:
            client.close()
