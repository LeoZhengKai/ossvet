# ossvet

> Vet any public GitHub repo before you clone it, install it, or run it.

`ossvet` is a local CLI tool that answers one question: **"Is it safe to use this?"**

It shallow-clones the repo into a throw-away temp directory, runs a fleet of
static scanners in parallel, and gives you a single verdict:

```
╭──────────────── OSS Vet Report ─────────────────╮
│ Repo:     https://github.com/some-org/some-pkg  │
│ Commit:   a3f7b2c91d04                          │
│ Verdict:  BLOCK / DO NOT RUN LOCALLY            │
│ Score:    82 / 100                              │
│ Duration: 4.1s                                  │
│                                                 │
│ Top Findings:                                   │
│   1. Bidirectional Unicode control character    │
│   2. Reverse-shell pattern in src/util.py:44    │
│   3. package.json postinstall script            │
│   4. Possible typosquat: `requestes`            │
╰─────────────────────────────────────────────────╯
```

It writes three report files you can read or commit:

| File | Contents |
|------|----------|
| `reports/report.md` | Human-readable findings, scanner table, recommendations |
| `reports/report.json` | Full structured findings (pipe into jq, CI scripts, etc.) |
| `reports/SKILL.md` | Security passport — pin commit hash, checklist to commit alongside the dep |

**It never executes a single line of the scanned repo's code.**

---

## Installation (one-time)

`ossvet` is a Python CLI. Install it once and it's available system-wide:

```bash
# Option A — pipx (recommended: isolated, no dep conflicts)
pipx install git+https://github.com/ossvet/ossvet

# Option B — pip into your active environment
pip install git+https://github.com/ossvet/ossvet

# Option C — dev install from source
git clone https://github.com/ossvet/ossvet
cd ossvet
pip install -e .
```

After installation the `ossvet` command works **from any directory** on your
machine — you don't need to be in the `ossvet` source folder.

---

## Quick start

```bash
# 1. Check what's installed
ossvet doctor

# 2. Vet a repo (fast mode, ~5s)
ossvet scan https://github.com/some-org/some-package

# 3. Vet a repo with all scanners (deep mode, ~60–120s)
ossvet scan https://github.com/some-org/some-package --deep
```

---

## Two scanning modes

### Fast (default) — ~5 seconds, no external tools needed

Runs five pure-Python scanners that catch the most dangerous patterns:

| Scanner | What it catches |
|---------|-----------------|
| `risky_files` | postinstall scripts, setup.py hooks, .vscode/tasks.json executables, CI workflow risks |
| `patterns` | curl-pipe-sh, reverse shells, obfuscated eval/exec, credential targeting, time bombs |
| `unicode_trojan` | CVE-2021-42574 Trojan Source — invisible BIDI chars, zero-width chars, Cyrillic homoglyphs |
| `dependency_hygiene` | Typosquatted package names, unpinned deps, non-registry sources |
| `provenance` | New maintainer accounts, single contributor, stale repo, star velocity spikes |

```bash
ossvet scan https://github.com/org/repo        # fast by default
```

### Deep (--deep) — ~60–120 seconds, external tools needed

Also runs professional-grade tools:

| Scanner | What it catches |
|---------|-----------------|
| `semgrep` | Static analysis (auto + supply-chain rulesets) |
| `syft` + `grype` | CVE audit of all declared dependencies |
| `gitleaks` | Secrets and credentials committed to git history |
| `scorecard` | OpenSSF supply-chain health checks |
| `modelscan` | Pickle-based ML weight files (arbitrary code execution on load) |

```bash
ossvet scan https://github.com/org/repo --deep
```

---

## Install the deep-scan tools

```bash
# macOS — let ossvet do it for you:
ossvet doctor --fix

# Or manually:
brew install semgrep syft grype gitleaks ossf/scorecard/scorecard
pip install modelscan
```

`ossvet doctor` shows exactly which tools are present and which are missing.
Every missing tool gracefully degrades — the fast scanners always run.

---

## Full user workflow

### Before adopting a new dependency

```bash
# Quick check before pip install / npm install
ossvet scan https://github.com/org/package

# If verdict is LOW RISK → proceed
# If verdict is REVIEW REQUIRED → read reports/report.md before deciding
# If verdict is BLOCK → do not install on your machine
```

### Deeper audit before merging a dep into production

```bash
ossvet scan https://github.com/org/package --deep --output-dir reports/audits/package-name
# Commit reports/audits/package-name/SKILL.md into your repo as a security passport
```

### CI gate — fail the build if a dep is risky

```bash
# In your CI pipeline:
ossvet scan https://github.com/org/package --fail-on=review
# Exit code 1 if verdict is REVIEW or worse
```

---

## Verdicts & scoring

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0–24 | **LOW RISK** (green) | No significant issues found |
| 25–59 | **REVIEW REQUIRED** (yellow) | Concerns worth reading before adopting |
| 60–100 | **BLOCK** (red) | Do not install or run on your machine |

**Hard overrides always force BLOCK regardless of score:**
- Bidirectional Unicode control characters (Trojan Source attack)
- Reverse-shell signature
- Cryptocurrency miner signature
- ModelScan CRITICAL finding in an ML weight file

---

## All flags

```bash
ossvet scan <github_url> [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--deep` | off | Also run external scanners (semgrep, grype, etc.) |
| `--output-dir` | `reports` | Where to write report files |
| `--fail-on` | `block` | Exit code 1 if verdict ≥ `low`/`review`/`block` |
| `--no-api` | off | Skip GitHub API calls (no provenance or scorecard) |
| `--keep-clone` | off | Don't delete the temp clone after scan |
| `--timeout` | `60` | Per-scanner subprocess timeout in seconds |
| `--skip` | – | Scanner names to skip, e.g. `--skip semgrep` |
| `--only` | – | Run only listed scanners, e.g. `--only patterns` |

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete; verdict below `--fail-on` threshold |
| `1` | Scan complete; verdict at or above `--fail-on` threshold |
| `2` | Scan couldn't start (clone failed, invalid URL, size limit hit) |
| `3` | Internal error |

---

## Security guarantees

- **Never executes repo code.** `setup.py` is parsed as an AST, not run. No `pip install`, `npm install`, `make`, or script execution.
- **Subprocess calls:** all use `shell=False`, list-form args, and a hard timeout.
- **Clone isolation:** always into `tempfile.mkdtemp(prefix="ossvet-")`, cleaned up on exit.
- **Binary files skipped:** null-byte heuristic; no file larger than 2 MB is pattern-scanned.
- **ANSI injection defence:** all external tool output is stripped before embedding in reports.
- **Refuses to run as root** on Linux.

---

## Development

```bash
git clone https://github.com/ossvet/ossvet
cd ossvet
pip install -e ".[dev]"

pytest                          # run tests
ruff check ossvet/              # lint
mypy ossvet/                    # type check
```

## Roadmap

| Version | Feature |
|---------|---------|
| **v0.1** (now) | Static analysis, fast + deep modes, rich terminal output |
| **v0.2** | Dynamic sandbox — Docker detonation, strace syscall tracing, network capture |
| **v0.3** | LLM reasoning layer — Claude/GPT natural-language executive summary + false-positive triage |

## License

MIT — see [LICENSE](LICENSE).
