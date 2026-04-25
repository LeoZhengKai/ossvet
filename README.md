# ossvet

> Decide whether an open-source GitHub repo is safe to inspect, install, or run.

`ossvet` is a local CLI that shallow-clones a public GitHub repository into a
temp directory and orchestrates a fleet of static security scanners — Semgrep,
Grype, Syft, Gitleaks, OpenSSF Scorecard, ModelScan — alongside its own
adversarial pure-Python checks (risky-file inspection, suspicious-pattern
grep, Unicode trojan detection, GitHub provenance signals, dependency
hygiene). The findings are fused into a single risk score and verdict:
**LOW RISK**, **REVIEW REQUIRED**, or **BLOCK**.

The tool **never executes code from the scanned repo**. v0.1 is purely
static analysis; dynamic sandbox detonation is on the v0.2 roadmap.

## Quick start

```bash
# Install
pipx install ossvet            # or: pip install ossvet

# Check which underlying scanners are available
ossvet doctor

# Scan a repo
ossvet scan https://github.com/some-org/some-repo
```

Reports are written to `./reports/`:
- `report.md` — human-readable summary
- `report.json` — full structured findings
- `SKILL.md` — auto-generated security passport for the repo
- `raw/*.json` — raw outputs from each external scanner

## Installing the underlying scanners

`ossvet` degrades gracefully when a scanner is missing — it just records the
gap and keeps going. But for a complete picture, install them.

### macOS (Homebrew)

```bash
brew install semgrep syft grype gitleaks
brew install ossf/scorecard/scorecard
pip install modelscan          # or: pipx install modelscan
```

### Linux

```bash
# Semgrep
pip install semgrep

# Syft + Grype (Anchore)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Gitleaks
# See https://github.com/gitleaks/gitleaks/releases for prebuilt binaries

# OpenSSF Scorecard
# See https://github.com/ossf/scorecard/releases for prebuilt binaries

# ModelScan
pip install modelscan
```

Run `ossvet doctor` after installation to confirm everything is reachable.

## Common flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output-dir` | `reports` | Where to write reports |
| `--keep-clone` | off | Retain the temp clone after scan |
| `--timeout` | `60` | Per-scanner subprocess timeout (seconds) |
| `--skip` | – | Scanner names to skip (repeatable) |
| `--only` | – | Run only the listed scanners (repeatable) |
| `--fail-on` | `block` | Exit non-zero if verdict ≥ this (`low`/`review`/`block`/`never`) |
| `--no-api` | off | Skip GitHub API provenance checks |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed; verdict below `--fail-on` threshold |
| 1 | Scan completed; verdict at or above `--fail-on` threshold |
| 2 | Scan could not complete (clone failed, invalid URL, …) |
| 3 | Internal error |

## Development

```bash
git clone https://github.com/ossvet/ossvet
cd ossvet
pip install -e ".[dev]"
pytest
ruff check ossvet/
mypy ossvet/
```

## License

MIT — see [LICENSE](LICENSE).
