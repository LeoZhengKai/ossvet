# ossvet — Roadmap

Current version: **v0.1.0** (static analysis only)

---

## v0.1 — Shipped ✅

Static analysis pipeline. Eleven scanners. Single trust verdict. No code execution.

**What's in it:**
- Fast mode (pure-Python, ~5s): risky_files, patterns, unicode_trojan, dependency_hygiene, provenance
- Deep mode (`--deep`, ~60–120s): + semgrep, syft+grype, gitleaks, scorecard, modelscan
- Outputs: `report.md`, `report.json`, `SKILL.md` security passport
- `ossvet doctor --fix` auto-installs missing tools
- Live streaming scanner progress in the terminal

**Hard constraints it upholds:**
- Never executes a single line of the scanned repo
- All subprocesses: `shell=False`, list args, hard timeout
- Clone into `tempfile.mkdtemp(prefix="ossvet-")`, cleaned up on exit
- Refuses to run as root on Linux

---

## v0.2 — Dynamic Analysis (Sandbox Detonation)

**Goal:** Go beyond static analysis. Actually *run* the repo in an isolated sandbox and observe what it does.

**The core insight:** Static analysis can be evaded. A sophisticated attacker can write malware that looks clean to every static scanner but only activates under specific runtime conditions. The only way to catch this is controlled detonation.

**New subcommand: `ossvet detonate <repo_url>`**

```bash
ossvet detonate https://github.com/org/suspicious-package
```

### What it does

1. Pulls a fresh Docker image (`python:3.11-slim` or similar)
2. Clones the repo inside the container
3. Runs the repo's entry point / setup script *inside the container only*
4. Simultaneously:
   - `strace -e trace=execve,openat,connect` — captures every syscall (what files did it open? what processes did it spawn? what network connections did it attempt?)
   - `tcpdump -w capture.pcap` — records all network traffic in a separate network namespace
5. Kills the container after a timeout
6. Analyses the capture:
   - Any `connect()` syscall to an external IP? → flag exfiltration attempt
   - Any `execve()` of an unexpected binary? → flag process injection
   - Any `openat()` of `~/.ssh`, `/etc/passwd`, or outside expected dirs? → flag credential access
   - Any DNS lookups or HTTP requests? → flag network exfiltration
7. Merges findings into `detonation_report.md` alongside the static report

### Architecture

```
ossvet detonate <url>
    │
    ▼
Pull Docker image (cached after first run)
    │
    ▼
docker run --network=none --rm \   ← no network by default
  --security-opt no-new-privileges \
  --read-only \                     ← filesystem is read-only
  --tmpfs /tmp \                    ← only /tmp is writable
  <image> <entrypoint>
    │
    ├── strace captures to strace.log
    ├── tcpdump captures to capture.pcap (separate net namespace for sniffing)
    └── container killed after DETONATION_TIMEOUT (default: 30s)
    │
    ▼
Analyse strace.log + capture.pcap
    │
    ▼
Merge with static report → detonation_report.md
```

### Hard requirements for v0.2

- **Docker is a hard dependency.** If Docker isn't installed, `ossvet detonate` exits with code 2 and a clear message.
- **Explicit user consent prompt** before detonation: "This will execute untrusted code in a Docker container. Type YES to continue."
- **Network namespace isolation:** `--network=none` by default. Flag `--allow-network` (with extra consent prompt) for repos that require network to initialise.
- **No persistent state:** container is `--rm` (auto-deleted). Nothing from the container touches the host filesystem except the report.
- **Platform note:** `strace` is Linux-only. On macOS, fall back to `dtruss` or `dtrace` (with a note that coverage is reduced). On macOS with Apple Silicon, Docker runs in a Linux VM anyway so `strace` inside the container works.

### New findings it catches that static analysis misses

| Attack | How detonation catches it |
|--------|--------------------------|
| Time bomb | Actually advances the clock inside the container to trigger date-gated payloads |
| Environment-sensitive malware | Spoofs `CI=false`, `GITHUB_ACTIONS=false` to trigger hostname-gated code |
| Lazy loader | Malware loaded only when a specific function is first called |
| Staged payload | setup.py downloads second-stage from the internet (caught by DNS capture even with `--network=none` failing) |
| Filesystem probe | Process tries to read `~/.ssh/id_rsa` (caught by strace `openat` trace) |

### Files to create

```
ossvet/
├── sandbox/
│   ├── __init__.py
│   ├── docker_runner.py      ← pulls image, runs container, manages lifecycle
│   ├── strace_parser.py      ← parses strace output into structured findings
│   ├── pcap_parser.py        ← parses tcpdump .pcap into network events
│   └── detonation_scanner.py ← BaseScanner subclass wrapping the above
└── main.py                   ← add `detonate` command
```

### Dependencies to add

```toml
# pyproject.toml — optional "sandbox" extra
[project.optional-dependencies]
sandbox = ["docker>=7.0", "scapy>=2.5"]  # scapy for pcap parsing
```

Install with: `pip install "ossvet[sandbox]"`

---

## v0.3 — LLM Reasoning Layer

**Goal:** Turn structured findings into an executive summary a non-security engineer can act on, and reduce false-positive fatigue.

**The core insight:** ossvet v0.1 + v0.2 produce a lot of structured data. A security engineer can read it. A product manager or a developer adopting a new library cannot. An LLM can bridge that gap — not by replacing the analysis, but by explaining it.

### New flag: `--explain`

```bash
ossvet scan https://github.com/org/repo --explain
```

Sends the structured `ScanResult` JSON to an LLM and asks for:

1. **Executive summary (3–4 sentences):** What is this repo? What are the key concerns? What should I do?
2. **False-positive triage:** For each finding, estimate likelihood it's a real threat vs. a false positive (e.g., `base64.b64decode` in a cryptography library is expected; in a simple web scraper it's suspicious).
3. **Context-aware recommendations:** "This is a data-processing library. The `os.system` call on line 44 of `utils.py` is particularly concerning because there's no input validation upstream."

### Architecture

```python
# ossvet/llm.py

def explain_scan(scan: ScanResult, *, model: str = "claude-sonnet-4-6") -> str:
    """Send structured findings to an LLM; return markdown explanation."""
    client = anthropic.Anthropic()
    prompt = _build_prompt(scan)
    response = client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
```

The prompt structure:
```
You are a security engineer reviewing an automated scan report.

Repository: <url>
Verdict: <BLOCK/REVIEW/LOW RISK>
Risk Score: <n>/100

Findings:
<structured list of findings with category, severity, file:line, description>

Scanner status:
<which tools ran, which were skipped>

Tasks:
1. Write a 3-4 sentence executive summary a non-security developer can understand.
2. For each HIGH or CRITICAL finding, assess: is this likely a real threat or a false positive?
3. Give one specific recommended next action.
```

### Privacy gate

The `--explain` flag will:
1. Print exactly what data will be sent to the LLM API before sending
2. Ask for confirmation: "Send findings to Anthropic Claude API? (yes/no)"
3. Allow `--explain --yes` to skip the prompt (for CI use)
4. Allow `--explain --model=local` to route to an Ollama instance instead

Never sends raw source code — only the structured `ScanResult` (scanner names, finding titles, categories, severities, file paths, line numbers). No actual file contents.

### Model support

| Flag | Routes to |
|------|-----------|
| `--model=claude` | Anthropic API (requires `ANTHROPIC_API_KEY`) |
| `--model=gpt4` | OpenAI API (requires `OPENAI_API_KEY`) |
| `--model=local` | Ollama at `localhost:11434` (free, private) |

### New output: `reports/explanation.md`

```markdown
## Executive Summary

This repository implements a data-scraping library with 847 stars. The scan
found three significant concerns: a bidirectional Unicode character in
`src/auth.py` line 44 that is almost certainly a Trojan Source attack
(CVE-2021-42574), a postinstall npm script that downloads and executes a
remote shell script, and a maintainer account created only 12 days ago.

## Finding Assessment

| Finding | Likely Real? | Reasoning |
|---------|-------------|-----------|
| BIDI control char in src/auth.py:44 | **Yes** | No legitimate reason for U+202E in an auth check |
| base64.b64decode in utils/crypto.py:12 | **Probably not** | File is a crypto utility; base64 is expected here |
| Unpinned `requests` in requirements.txt | **Minor** | Low risk, just a hygiene issue |

## Recommended Action

Do not install this package. The BIDI character in the auth module combined
with the new maintainer account strongly suggests a supply-chain attack.
File a report at https://github.com/org/repo/issues and notify PyPI security.
```

### Dependencies to add

```toml
[project.optional-dependencies]
llm = ["anthropic>=0.40", "openai>=1.0"]
```

Install with: `pip install "ossvet[llm]"`

---

## v0.4 — Ecosystem & Distribution

Beyond the core tool, this release makes ossvet part of the developer workflow.

### GitHub Action

```yaml
# .github/workflows/vet-deps.yml
- uses: ossvet/action@v1
  with:
    repo: https://github.com/new-dep/to-vet
    fail-on: review
```

Run ossvet in your own CI pipeline to gate PRs that bump dependencies.

### Pre-install hooks

```bash
# Intercept pip installs
ossvet hook install --pip
# Now: pip install <package> → ossvet scans it first, asks to confirm if REVIEW/BLOCK

# Intercept npm installs
ossvet hook install --npm
```

### Scan history & diff

```bash
ossvet scan https://github.com/org/repo
# → saved to ~/.ossvet/history/<repo-hash>/<timestamp>/

ossvet diff https://github.com/org/repo
# → compares latest scan to the previous one
# "2 new HIGH findings since last scan on 2026-04-20 @ abc1234"
```

### Web dashboard (local)

```bash
ossvet serve
# → opens http://localhost:7777
# → browse scan history, compare verdicts, search findings
```

---

## Summary timeline

| Version | Focus | New commands | Hard dependency |
|---------|-------|-------------|-----------------|
| **v0.1** ✅ | Static analysis, 11 scanners, fast+deep modes | `scan`, `doctor`, `version` | None (pure Python + optional brew tools) |
| **v0.2** | Dynamic sandbox detonation | `detonate` | Docker |
| **v0.3** | LLM reasoning + false-positive triage | `scan --explain` | Anthropic/OpenAI/Ollama API key |
| **v0.4** | GitHub Action, pip/npm hooks, scan history | `diff`, `serve`, `hook` | None new |

---

## Design principle for all future versions

The plugin architecture is already in place: add a new scanner under `ossvet/scanners/` or `ossvet/sandbox/`, register it in `get_scanners()`, and the scoring, reporting, and SKILL.md output picks it up automatically. `scoring.py` and `reporting.py` do not need to change for new scanner types.
