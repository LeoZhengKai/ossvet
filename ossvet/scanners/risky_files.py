"""Risky-file inspection. Pure-Python — no execution of repo code.

Specifically, we **never** import or `exec` setup.py: we parse it via `ast`.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import yaml

from ossvet.models import Finding, ScannerResult, Severity
from ossvet.scanners.base import BaseScanner

_NPM_LIFECYCLE_KEYS = {"preinstall", "install", "postinstall", "prepare", "preuninstall", "postuninstall"}
_VSCODE_EXEC_KEYS = {"command", "args", "program", "shellArgs"}

_DOCKER_RISKY_RE = re.compile(
    r"^\s*(RUN\s+(curl|wget)|ADD\s+https?://)",
    re.IGNORECASE,
)

_THIRD_PARTY_ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@([A-Za-z0-9_.-]+)$")


class RiskyFilesScanner(BaseScanner):
    name = "risky_files"
    required_tool = None

    def run(self, repo_path: Path, **kwargs: object) -> ScannerResult:
        start = self._now()
        findings: list[Finding] = []
        try:
            self._inspect_package_json(repo_path, findings)
            self._inspect_setup_py(repo_path, findings)
            self._inspect_vscode(repo_path, findings)
            self._inspect_devcontainer(repo_path, findings)
            self._inspect_dockerfiles(repo_path, findings)
            self._inspect_compose(repo_path, findings)
            self._inspect_workflows(repo_path, findings)
            self._inspect_makefile(repo_path, findings)
        except Exception as exc:  # noqa: BLE001
            return self._error(f"risky_files scanner failed: {exc!r}", duration=self._now() - start)
        return self._ok(findings, duration=self._now() - start)

    # -- individual file inspectors --------------------------------------

    def _inspect_package_json(self, repo: Path, out: list[Finding]) -> None:
        for path in repo.rglob("package.json"):
            if "node_modules" in path.parts:
                continue
            data = self._load_json(path)
            if not isinstance(data, dict):
                continue
            scripts = data.get("scripts")
            if not isinstance(scripts, dict):
                continue
            for hook in _NPM_LIFECYCLE_KEYS:
                cmd = scripts.get(hook)
                if not isinstance(cmd, str):
                    continue
                out.append(
                    Finding(
                        scanner=self.name,
                        category="npm_install_script",
                        severity=Severity.HIGH,
                        title=f"package.json defines {hook} script",
                        description=f"Lifecycle script `{hook}` runs at install time: {cmd[:200]}",
                        file_path=str(path.relative_to(repo)),
                        rule_id=f"npm-{hook}",
                    )
                )

    def _inspect_setup_py(self, repo: Path, out: list[Finding]) -> None:
        for path in repo.rglob("setup.py"):
            if "node_modules" in path.parts:
                continue
            text = self._read(path)
            if text is None:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue

            # Look for any class deriving from setuptools/distutils install commands,
            # or for a setup() call passing a custom cmdclass.
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    for base in node.bases:
                        base_name = self._dotted_name(base) or ""
                        if any(kw in base_name for kw in ("install", "develop", "build_py", "egg_info")):
                            out.append(
                                Finding(
                                    scanner=self.name,
                                    category="setup_py_hook",
                                    severity=Severity.HIGH,
                                    title=f"setup.py defines a custom command class ({node.name})",
                                    description=f"Class `{node.name}` derives from `{base_name}` — runs during install.",
                                    file_path=str(path.relative_to(repo)),
                                    line_number=node.lineno,
                                    rule_id="setup-py-cmdclass",
                                )
                            )
                if isinstance(node, ast.Call) and self._dotted_name(node.func) in {"setup", "setuptools.setup"}:
                    for kw in node.keywords:
                        if kw.arg in {"cmdclass", "dependency_links"}:
                            out.append(
                                Finding(
                                    scanner=self.name,
                                    category="setup_py_hook",
                                    severity=Severity.HIGH,
                                    title=f"setup() passes `{kw.arg}=...`",
                                    description=f"setup() argument `{kw.arg}` indicates custom install behaviour.",
                                    file_path=str(path.relative_to(repo)),
                                    line_number=getattr(kw.value, "lineno", node.lineno),
                                    rule_id="setup-py-kwarg",
                                )
                            )

    def _inspect_vscode(self, repo: Path, out: list[Finding]) -> None:
        for cfg_name in ("tasks.json", "launch.json"):
            for path in repo.rglob(f".vscode/{cfg_name}"):
                data = self._load_json(path)
                if not isinstance(data, dict):
                    continue

                def visit(node: Any) -> None:
                    if isinstance(node, dict):
                        for k, v in node.items():
                            if k in _VSCODE_EXEC_KEYS and (isinstance(v, str) or isinstance(v, list)):
                                out.append(
                                    Finding(
                                        scanner=self.name,
                                        category="vscode_exec_config",
                                        severity=Severity.HIGH,
                                        title=f".vscode/{cfg_name} declares an executable `{k}`",
                                        description=f"Field `{k}` in {cfg_name}: {str(v)[:200]}",
                                        file_path=str(path.relative_to(repo)),
                                        rule_id="vscode-exec",
                                    )
                                )
                            visit(v)
                    elif isinstance(node, list):
                        for item in node:
                            visit(item)

                visit(data)

    def _inspect_devcontainer(self, repo: Path, out: list[Finding]) -> None:
        candidates = list(repo.rglob(".devcontainer/devcontainer.json"))
        candidates += list(repo.rglob(".devcontainer.json"))
        for path in candidates:
            data = self._load_json(path)
            if not isinstance(data, dict):
                continue
            for key in ("postCreateCommand", "postStartCommand", "onCreateCommand", "updateContentCommand"):
                if data.get(key):
                    out.append(
                        Finding(
                            scanner=self.name,
                            category="vscode_exec_config",
                            severity=Severity.HIGH,
                            title=f"devcontainer declares `{key}`",
                            description=f"{key}: {str(data[key])[:200]}",
                            file_path=str(path.relative_to(repo)),
                            rule_id="devcontainer-exec",
                        )
                    )

    def _inspect_dockerfiles(self, repo: Path, out: list[Finding]) -> None:
        for path in list(repo.rglob("Dockerfile")) + list(repo.rglob("*.dockerfile")):
            text = self._read(path)
            if text is None:
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                if _DOCKER_RISKY_RE.match(line):
                    out.append(
                        Finding(
                            scanner=self.name,
                            category="ci_workflow_risk",
                            severity=Severity.MEDIUM,
                            title="Dockerfile fetches remote content at build time",
                            description=line.strip()[:200],
                            file_path=str(path.relative_to(repo)),
                            line_number=line_no,
                            rule_id="dockerfile-remote-fetch",
                        )
                    )

    def _inspect_compose(self, repo: Path, out: list[Finding]) -> None:
        for path in list(repo.rglob("docker-compose.yml")) + list(repo.rglob("docker-compose.yaml")):
            data = self._load_yaml(path)
            if not isinstance(data, dict):
                continue
            services = data.get("services") or {}
            if not isinstance(services, dict):
                continue
            for svc, sdata in services.items():
                if not isinstance(sdata, dict):
                    continue
                if sdata.get("privileged") is True:
                    out.append(
                        Finding(
                            scanner=self.name,
                            category="ci_workflow_risk",
                            severity=Severity.HIGH,
                            title=f"docker-compose service `{svc}` requests privileged: true",
                            description="Privileged containers can escape the container boundary.",
                            file_path=str(path.relative_to(repo)),
                            rule_id="compose-privileged",
                        )
                    )

    def _inspect_workflows(self, repo: Path, out: list[Finding]) -> None:
        wf_dir = repo / ".github" / "workflows"
        if not wf_dir.is_dir():
            return
        for path in wf_dir.glob("*.y*ml"):
            data = self._load_yaml(path)
            if not isinstance(data, dict):
                continue
            on = data.get("on") or data.get(True)  # YAML may parse `on` as True
            on_keys: set[str] = set()
            if isinstance(on, str):
                on_keys.add(on)
            elif isinstance(on, list):
                on_keys.update(x for x in on if isinstance(x, str))
            elif isinstance(on, dict):
                on_keys.update(on.keys())  # type: ignore[arg-type]
            if "pull_request_target" in on_keys:
                out.append(
                    Finding(
                        scanner=self.name,
                        category="ci_workflow_risk",
                        severity=Severity.HIGH,
                        title="Workflow uses pull_request_target trigger",
                        description=(
                            "pull_request_target runs with write secrets in the context of "
                            "untrusted code. Frequent vector for supply-chain attacks."
                        ),
                        file_path=str(path.relative_to(repo)),
                        rule_id="gh-pull-request-target",
                    )
                )

            jobs = data.get("jobs") or {}
            if not isinstance(jobs, dict):
                continue
            for jname, jdata in jobs.items():
                if not isinstance(jdata, dict):
                    continue
                steps = jdata.get("steps") or []
                if not isinstance(steps, list):
                    continue
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    uses = step.get("uses")
                    if isinstance(uses, str):
                        m = _THIRD_PARTY_ACTION_RE.match(uses)
                        if m and not re.fullmatch(r"[a-f0-9]{40}", m.group(1)):
                            out.append(
                                Finding(
                                    scanner=self.name,
                                    category="ci_workflow_risk",
                                    severity=Severity.MEDIUM,
                                    title=f"Workflow uses third-party action without SHA pin: {uses}",
                                    description="Pin to a full commit SHA, not a tag/branch.",
                                    file_path=str(path.relative_to(repo)),
                                    rule_id="gh-action-unpinned",
                                )
                            )
                    run = step.get("run")
                    if isinstance(run, str) and "${{" in run and "github.event" in run:
                        out.append(
                            Finding(
                                scanner=self.name,
                                category="ci_workflow_risk",
                                severity=Severity.HIGH,
                                title=f"Workflow `{jname}` interpolates github.event into a shell run step",
                                description="Direct interpolation of github.event.* into `run` enables script injection.",
                                file_path=str(path.relative_to(repo)),
                                rule_id="gh-script-injection",
                            )
                        )

    def _inspect_makefile(self, repo: Path, out: list[Finding]) -> None:
        for path in repo.rglob("Makefile"):
            text = self._read(path)
            if text is None:
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                if re.search(r"\bcurl[^|]*\|\s*(bash|sh)", line):
                    out.append(
                        Finding(
                            scanner=self.name,
                            category="ci_workflow_risk",
                            severity=Severity.HIGH,
                            title="Makefile pipes curl into a shell",
                            description=line.strip()[:200],
                            file_path=str(path.relative_to(repo)),
                            line_number=line_no,
                            rule_id="makefile-curl-pipe",
                        )
                    )

    # -- low-level helpers -----------------------------------------------

    @staticmethod
    def _load_json(path: Path) -> Any:
        text = RiskyFilesScanner._read(path)
        if text is None:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _load_yaml(path: Path) -> Any:
        text = RiskyFilesScanner._read(path)
        if text is None:
            return None
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError:
            return None

    @staticmethod
    def _read(path: Path) -> str | None:
        try:
            if path.is_symlink():
                return None
            if path.stat().st_size > 2_000_000:
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    @staticmethod
    def _dotted_name(node: ast.AST) -> str | None:
        """Return dotted name for `Name` / `Attribute` nodes; None otherwise."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = RiskyFilesScanner._dotted_name(node.value)
            if base is None:
                return None
            return f"{base}.{node.attr}"
        return None
