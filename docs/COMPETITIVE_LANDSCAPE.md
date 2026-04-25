# ossvet — Competitive Landscape

*How ossvet differs from existing security tools.*

---

## The fundamental question each tool is designed to answer

This is the most important distinction in this space. Before comparing features, understand **what problem each tool solves**:

| Tool | Core question it answers |
|------|--------------------------|
| Semgrep | "Does MY code have security bugs or bad patterns?" |
| SonarQube | "What is the overall quality and security health of MY codebase?" |
| Bearer CLI | "Does MY code leak sensitive data or mishandle PII?" |
| Snyk | "Do MY declared dependencies have known CVEs?" |
| Sonatype OSS Index | "Is THIS specific package version known-vulnerable?" |
| Checkmarx One | "Does MY code have security vulnerabilities (SAST + SCA)?" |
| Veracode | "Does MY application pass security compliance gates (SAST + DAST + SCA)?" |
| Socket.dev | "Is THIS npm/PyPI package acting maliciously right now?" |
| OpenSSF Scorecard | "Does THIS GitHub repo follow supply-chain best practices?" |
| **ossvet** | **"Should I trust this GitHub repo enough to clone, install, or run it?"** |

The key word in ossvet's question is **"trust"** — and the key assumption is that **the repo owner might be malicious**. Every other tool in this list assumes you are scanning code that was written in good faith (your own code, or packages from authors who are trying to help you). ossvet is the only tool designed from the adversarial assumption: *treat every byte as untrusted*.

---

## Feature comparison

| Capability | ossvet | Semgrep | SonarQube | Snyk | Socket.dev | Scorecard |
|-----------|--------|---------|-----------|------|-----------|-----------|
| **Trojan Source / BIDI char detection** | ✅ | ❌ | ❌ | ❌ | ⚠️ partial | ❌ |
| **Typosquat detection** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **setup.py install hook detection** | ✅ (AST) | ⚠️ rules | ❌ | ⚠️ | ✅ | ❌ |
| **package.json postinstall detection** | ✅ | ⚠️ rules | ❌ | ⚠️ | ✅ | ❌ |
| **GitHub provenance signals** | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **CVE dependency scanning** | ✅ (via grype) | ✅ (paid) | ✅ (paid) | ✅ | ✅ | ❌ |
| **Secret scanning** | ✅ (via gitleaks) | ❌ | ✅ (paid) | ✅ | ✅ | ❌ |
| **SAST (code quality)** | ✅ (via semgrep) | ✅ | ✅ | ✅ | ❌ | ❌ |
| **ML model (pickle) scanning** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Runs entirely locally** | ✅ | ✅ | ⚠️ CE only | ✅ CLI | ❌ | ✅ |
| **No account / API key required** | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Designed for third-party repo intake** | ✅ | ❌ | ❌ | ❌ | ⚠️ npm/PyPI only | ⚠️ hygiene only |
| **Single binary verdict (trust/block)** | ✅ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| **SKILL.md security passport output** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Vets a URL before you clone** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Open source & free** | ✅ | ✅ CE | ✅ CE | ❌ | ❌ | ✅ |

---

## Tool-by-tool breakdown

### Semgrep

**What it is:** A static analysis engine. You write (or use existing) patterns and it finds matching code.

**Who uses it:** Development teams scanning their own codebase for security bugs, bad patterns, and policy violations. Used in CI pipelines.

**What it does NOT do:**
- It doesn't have an opinion about whether a third-party repo is trustworthy
- No provenance signals (GitHub account age, contributor count, star velocity)
- No Trojan Source detection
- No typosquat detection
- No concept of "should I adopt this?"

**Where ossvet uses it:** ossvet runs semgrep (via `--deep`) as one of 11 scanners. We use the `auto` + `supply-chain` rulesets and fold the findings into the unified score.

**Pricing:** Free open-source Community edition for CLI. Semgrep Team/Enterprise (paid) adds managed platform, more rules.

---

### SonarQube / SonarCloud

**What it is:** Code quality + security platform for ongoing monitoring of YOUR codebase. Tracks code smells, coverage, duplicate code, and security hotspots over time.

**Who uses it:** Engineering teams who want a dashboard of their own codebase's health. Common in enterprise CI pipelines.

**Key difference from ossvet:** SonarQube is designed to be integrated *into your project*. You point it at your own repo and it tracks quality trends over months. It is not designed to quickly answer "can I trust this repo I just found on GitHub?"

**Pricing:** Community edition is free/self-hosted. SonarCloud (SaaS) free for public repos, paid for private. Advanced security features (SCA, deeper SAST) require paid tier.

---

### Bearer CLI

**What it is:** A SAST tool with a focus on **data security** — where does sensitive/personal data flow in your code, is it being logged or sent to third parties, are privacy policies violated?

**Key difference:** Bearer is specifically about data flows and privacy compliance (GDPR, SOC 2, HIPAA). It's not a supply-chain or trust tool at all. Scans your own code.

**Pricing:** Fully open source.

---

### Snyk

**What it is:** SaaS platform for vulnerability management. Scans your declared dependencies for CVEs (SCA), your code for bugs (SAST), your containers, and your IaC configs.

**Who uses it:** Dev teams who want a managed service to track and fix dependency vulnerabilities in their own projects.

**Key difference:** Snyk is reactive — it tells you about vulnerabilities *in things you've already adopted*. ossvet is proactive — it helps you decide *before* adoption. Snyk also requires a cloud account and sends data to Snyk's servers.

**Pricing:** Free tier (limited scans), paid plans from $25/dev/month. No fully local/private mode.

---

### Sonatype OSS Index / Lifecycle

**What it is:** The closest tool to ossvet in *intent*. Sonatype maintains a database of known-vulnerable and known-malicious packages. Their OSS Index is a free API; Lifecycle is the enterprise product.

**Overlap with ossvet:**
- Sonatype does flag some Trojan Source attacks (they have explicit CVE-2021-42574 detection)
- They detect malicious packages based on their database of known bad packages

**Key differences from ossvet:**
- Sonatype works at the **package level** — it checks if `requests==2.25.0` is in a vulnerability database. ossvet works at the **repo level** — it reads the actual source code of the repo and looks for adversarial patterns.
- Sonatype can only flag *known* malicious packages (database lookup). ossvet can detect *novel* attacks like a new Trojan Source variant or a new reverse-shell pattern.
- Sonatype Lifecycle is enterprise/paid. OSS Index is a free API but not a CLI you run against raw source.

**Pricing:** OSS Index API is free. Lifecycle is enterprise pricing.

---

### Checkmarx One

**What it is:** Enterprise SAST + SCA + DAST + supply-chain security platform. Cloud-hosted, designed for regulated industries (finance, healthcare).

**Key difference:** Enterprise compliance tool. Designed to prove to auditors that your own software was scanned. Expensive, cloud-only, requires extensive setup. Not a quick "should I clone this?" CLI.

**Pricing:** Enterprise contract pricing (typically $50k+/year).

---

### Veracode

**What it is:** Similar to Checkmarx — enterprise application security testing. Focuses on SAST + DAST + SCA for compliance and certification (SOC2, PCI-DSS proofs).

**Key difference:** Same story as Checkmarx — designed for proving compliance of your own software, not for OSS intake decisions. Cloud-only SaaS.

**Pricing:** Enterprise pricing.

---

### Socket.dev ⚠️ Most similar competitor

**What it is:** The closest thing to ossvet in the market. Socket analyzes npm and PyPI packages for supply-chain risk *before you install them*. It looks at behavioral signals: does this package have install scripts? Did it suddenly add network access? Did the maintainer change? Does it contain obfuscated code?

**Genuine overlaps with ossvet:**
- Typosquatting detection
- Install hook detection (postinstall, setup.py)
- Maintainer change alerts
- Obfuscation detection
- Works pre-adoption

**Key differences from ossvet:**
- Socket is **SaaS + npm/PyPI registry focused** — it works by hooking into the package registry, not by scanning raw GitHub repos. You can't point Socket at an arbitrary GitHub URL before it's a published package.
- Socket requires a cloud account and sends package metadata to Socket's servers
- No Trojan Source / BIDI detection
- No ML model scanning
- No SKILL.md passport output
- No unified risk score / single-verdict output
- No integration of external tools (semgrep, grype, gitleaks)

**Pricing:** Free for public open source. Team/Enterprise paid plans.

---

### OpenSSF Scorecard

**What it is:** Checks whether a GitHub repo follows supply-chain security best practices. Scores 0–10 on ~18 checks: are dependencies pinned? Are releases signed? Are GitHub Actions workflows safe? Is the project maintained?

**Overlap:** ossvet already wraps Scorecard as one of its 11 scanners (in `--deep` mode). You get Scorecard's findings plus 10 other scanners plus a unified verdict.

**Key difference:** Scorecard only checks *hygiene practices* — it doesn't look at the actual source code for malicious patterns, Trojan Source, reverse shells, or crypto miners.

**Pricing:** Fully open source, free.

---

## The honest positioning

ossvet sits at the intersection of three things that currently exist only separately:

```
Semgrep/Bearer (code-level static analysis)
    +
Socket.dev/Sonatype (supply-chain intent signals)
    +
Scorecard/provenance (repo health + trust signals)
    +
ML model security (modelscan)
    +
Adversarial-first assumption (Trojan Source, reverse shells, time bombs)
    =
ossvet: a single trust verdict before you clone anything
```

The closest single competitor is **Socket.dev** — but it is SaaS-only, npm/PyPI focused, and lacks the adversarial source-code analysis (BIDI trojans, reverse shells, time bombs).

### What ossvet does that nothing else does (combined)

1. **Trojan Source detection** — scanning for invisible BIDI control characters in source code
2. **Vetting an arbitrary GitHub URL** before it's even a published package
3. **Unified single verdict** across 11 scanners with a capped risk score
4. **SKILL.md passport** — committable audit artifact pinned to a commit SHA
5. **ML model pickle scanning** — critical gap as AI/ML repos proliferate
6. **Fully local, no account** — your code and scanned repos never leave your machine

---

## When to use which tool

| Scenario | Best tool |
|----------|-----------|
| I found a GitHub repo and want to adopt it — is it safe? | **ossvet** |
| My team's own codebase needs ongoing CVE monitoring | Snyk or Dependabot |
| I want to enforce code quality rules in my own PR pipeline | Semgrep or SonarQube |
| I need enterprise compliance reports (SOC2, PCI-DSS) | Checkmarx or Veracode |
| I want to monitor npm installs in my team's projects | Socket.dev |
| I want to check if a specific package version has a CVE | Sonatype OSS Index / deps.dev |
| I want to score a GitHub repo's security hygiene | OpenSSF Scorecard |
