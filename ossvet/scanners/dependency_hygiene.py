"""Dependency hygiene scanner: typosquats + install hooks + unpinned deps."""

from __future__ import annotations

import ast
import json
import re
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from rapidfuzz.distance import Levenshtein

from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner

_PY_STDLIB_HINT: frozenset[str] = frozenset(
    {
        "abc", "argparse", "ast", "asyncio", "base64", "collections",
        "concurrent", "contextlib", "copy", "csv", "ctypes", "dataclasses",
        "datetime", "decimal", "enum", "fnmatch", "functools", "getpass",
        "glob", "hashlib", "html", "http", "importlib", "inspect", "io",
        "ipaddress", "itertools", "json", "logging", "math", "os", "pathlib",
        "pickle", "platform", "queue", "random", "re", "secrets", "shutil",
        "signal", "socket", "sqlite3", "ssl", "stat", "string", "struct",
        "subprocess", "sys", "tempfile", "textwrap", "threading", "time",
        "timeit", "traceback", "types", "typing", "unicodedata", "urllib",
        "uuid", "warnings", "weakref", "xml", "zipfile", "zlib",
    }
)

_JS_BUILTIN_HINT: frozenset[str] = frozenset(
    {
        "fs", "path", "os", "child_process", "http", "https", "url",
        "stream", "buffer", "events", "util", "crypto", "tls", "net",
        "querystring", "zlib", "process", "assert", "console",
    }
)

_JS_REQUIRE_RE = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
_JS_FROM_RE = re.compile(r"""\bfrom\s+['"]([^'"]+)['"]""")
_JS_IMPORT_RE = re.compile(r"""\bimport\s+['"]([^'"]+)['"]""")


class DependencyHygieneScanner(BaseScanner):
    name = "dependency_hygiene"
    required_tool = None

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        start = self._now()
        findings: list[Finding] = []
        try:
            self._check_typosquat_python(repo_path, findings)
            self._check_typosquat_js(repo_path, findings)
            self._check_unpinned_python(repo_path, findings)
            self._check_unpinned_npm(repo_path, findings)
        except Exception as exc:  # noqa: BLE001
            return self._error(f"dependency_hygiene scanner failed: {exc!r}", duration=self._now() - start)
        return self._ok(findings, duration=self._now() - start)

    # -- typosquat detection ---------------------------------------------

    def _check_typosquat_python(self, repo: Path, out: list[Finding]) -> None:
        popular = _load_popular("popular_pypi.json")
        seen: set[tuple[str, str]] = set()
        for path in repo.rglob("*.py"):
            if any(part in {".git", "node_modules", ".venv", "venv"} for part in path.parts):
                continue
            try:
                if path.stat().st_size > 1_000_000:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(text)
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names.extend(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    names.append(node.module.split(".")[0])
                for n in names:
                    if not n or n in _PY_STDLIB_HINT:
                        continue
                    nl = n.lower()
                    if nl in popular:
                        continue
                    near = _nearest(nl, popular)
                    if near is not None and (path.name, n) not in seen:
                        seen.add((path.name, n))
                        out.append(
                            Finding(
                                scanner=self.name,
                                category="typosquat_suspect",
                                severity=Severity.MEDIUM,
                                title=f"Possible typosquat: imports `{n}` (close to `{near}`)",
                                description=(
                                    f"Module `{n}` is one or two edits away from popular package "
                                    f"`{near}`. Verify before installing."
                                ),
                                file_path=str(path.relative_to(repo)),
                                line_number=getattr(node, "lineno", None),
                                rule_id="typosquat-py",
                            )
                        )

    def _check_typosquat_js(self, repo: Path, out: list[Finding]) -> None:
        popular = _load_popular("popular_npm.json")
        seen: set[tuple[str, str]] = set()
        for ext in ("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs"):
            for path in repo.rglob(ext):
                if "node_modules" in path.parts or ".git" in path.parts:
                    continue
                try:
                    if path.stat().st_size > 1_000_000:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                names: set[str] = set()
                for rx in (_JS_REQUIRE_RE, _JS_FROM_RE, _JS_IMPORT_RE):
                    for m in rx.finditer(text):
                        spec = m.group(1)
                        if spec.startswith(".") or spec.startswith("/"):
                            continue  # relative
                        # @scope/name → keep the full @scope/name string
                        first = spec.split("/")
                        if spec.startswith("@") and len(first) >= 2:
                            mod = "/".join(first[:2])
                        else:
                            mod = first[0]
                        names.add(mod)
                for n in names:
                    if not n or n in _JS_BUILTIN_HINT:
                        continue
                    nl = n.lower()
                    if nl in popular:
                        continue
                    near = _nearest(nl, popular)
                    if near is not None and (path.name, n) not in seen:
                        seen.add((path.name, n))
                        out.append(
                            Finding(
                                scanner=self.name,
                                category="typosquat_suspect",
                                severity=Severity.MEDIUM,
                                title=f"Possible typosquat: imports `{n}` (close to `{near}`)",
                                description=(
                                    f"Module `{n}` is one or two edits away from popular package `{near}`."
                                ),
                                file_path=str(path.relative_to(repo)),
                                rule_id="typosquat-js",
                            )
                        )

    # -- unpinned dependency detection -----------------------------------

    def _check_unpinned_python(self, repo: Path, out: list[Finding]) -> None:
        for path in repo.rglob("requirements*.txt"):
            if "node_modules" in path.parts:
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, raw in enumerate(lines, 1):
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith(("-r", "--", "-c")):
                    continue
                # Git/url/local entries are different shape — also flagged.
                if line.startswith(("git+", "http://", "https://", "file://", "/")):
                    out.append(
                        Finding(
                            scanner=self.name,
                            category="unpinned_deps",
                            severity=Severity.LOW,
                            title="requirements entry uses non-PyPI source",
                            description=line[:200],
                            file_path=str(path.relative_to(repo)),
                            line_number=i,
                            rule_id="req-non-pypi",
                        )
                    )
                    continue
                if "==" not in line and "@" not in line:
                    out.append(
                        Finding(
                            scanner=self.name,
                            category="unpinned_deps",
                            severity=Severity.LOW,
                            title="Unpinned Python requirement",
                            description=line[:200],
                            file_path=str(path.relative_to(repo)),
                            line_number=i,
                            rule_id="req-unpinned",
                        )
                    )

    def _check_unpinned_npm(self, repo: Path, out: list[Finding]) -> None:
        for path in repo.rglob("package.json"):
            if "node_modules" in path.parts:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(section)
                if not isinstance(deps, dict):
                    continue
                for name, spec in deps.items():
                    if not isinstance(spec, str):
                        continue
                    if spec in {"*", "latest"} or spec.startswith(("^", "~", ">", "<")):
                        out.append(
                            Finding(
                                scanner=self.name,
                                category="unpinned_deps",
                                severity=Severity.LOW,
                                title=f"Unpinned npm dep `{name}`: {spec}",
                                description=f"In `{section}` of {path.name}.",
                                file_path=str(path.relative_to(repo)),
                                rule_id="npm-unpinned",
                            )
                        )


# -- helpers -----------------------------------------------------------------

@lru_cache(maxsize=2)
def _load_popular(filename: str) -> frozenset[str]:
    try:
        raw = files("ossvet.data").joinpath(filename).read_text(encoding="utf-8")
        data = json.loads(raw)
        return frozenset(name.lower() for name in data if isinstance(name, str))
    except (FileNotFoundError, json.JSONDecodeError, ModuleNotFoundError):
        return frozenset()


def _nearest(name: str, pool: frozenset[str]) -> str | None:
    """Return the closest popular package within Levenshtein distance ≤ 2.

    Returns None if `name` is identical to a popular package, or if no popular
    package is within distance 2.
    """
    if name in pool:
        return None
    if len(name) < 4:
        return None  # too short to be a meaningful typosquat signal
    best: tuple[int, str] | None = None
    for candidate in pool:
        if abs(len(candidate) - len(name)) > 2:
            continue
        d = Levenshtein.distance(name, candidate)
        if d == 0:
            return None
        if 1 <= d <= 2:
            if best is None or d < best[0]:
                best = (d, candidate)
    return best[1] if best else None
