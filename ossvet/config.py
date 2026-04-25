"""Centralised configuration: scoring weights, regex patterns, thresholds."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Resource limits & timeouts
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT: int = 60
MAX_REPO_SIZE_KB: int = 500 * 1024
MAX_SCAN_FILE_BYTES: int = 2_000_000
GITHUB_API_TIMEOUT: int = 15

# Extensions of source files we are willing to read as text.
TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".go", ".rs", ".rb", ".java", ".kt", ".kts", ".scala",
        ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".m", ".swift",
        ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
        ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
        ".md", ".rst", ".txt", ".env", ".dockerfile",
        ".html", ".htm", ".xml", ".vue", ".svelte",
        ".sql", ".graphql", ".proto",
        ".lock",
    }
)

# Filenames (no extension) we always treat as text.
TEXT_FILENAMES: frozenset[str] = frozenset(
    {
        "Dockerfile", "Makefile", "Rakefile", "Gemfile", "Procfile",
        "requirements.txt", "pyproject.toml", "package.json", "yarn.lock",
        "package-lock.json", "pnpm-lock.yaml", "go.mod", "go.sum",
        ".gitignore", ".gitattributes", "LICENSE", "README",
    }
)

# Directories we always skip.
SKIP_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}
)

# Extensions whose presence triggers ModelScan.
ML_WEIGHT_EXTENSIONS: frozenset[str] = frozenset(
    {".pkl", ".pt", ".pth", ".h5", ".bin", ".onnx", ".safetensors", ".joblib", ".ckpt"}
)


# ---------------------------------------------------------------------------
# Suspicious patterns (PRD §5.8 — verbatim, plus minor crypto-miner additions)
# ---------------------------------------------------------------------------

SUSPICIOUS_PATTERNS: dict[str, str] = {
    # Remote execution
    "curl_pipe_sh":        r"curl[^|]*\|\s*(bash|sh|zsh)",
    "wget_pipe_sh":        r"wget[^|]*\|\s*(bash|sh|zsh)",
    "eval_call":           r"\beval\s*\(",
    "exec_call":           r"\bexec\s*\(",
    "os_system":           r"os\.system\s*\(",
    "subprocess_shell":    r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True",
    "node_child_proc":     r"child_process\.(exec|execSync|spawn)",

    # Obfuscation
    "base64_decode_py":    r"base64\.(b64decode|decodebytes)",
    "base64_decode_js":    r"\batob\s*\(",
    "hex_decode":          r"codecs\.decode\([^,]+,\s*['\"]hex['\"]",
    "rot13":               r"codecs\.decode\([^,]+,\s*['\"]rot_?13['\"]",

    # Credential targeting
    "ssh_key_read":        r"~/\.ssh/|/\.ssh/id_",
    "aws_env":             r"AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID",
    "private_key_marker":  r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----",
    "passwd_read":         r"/etc/(passwd|shadow)",

    # Reverse shell signatures
    "nc_reverse":          r"\bnc\s+-[elvpn]*e\b",
    "bash_tcp":            r"/dev/tcp/",
    "ps_encoded":          r"powershell\s+-[eE]nc(odedCommand)?",
    "ps_webreq":           r"Invoke-WebRequest|Invoke-Expression|IEX\s*\(",

    # Time bombs
    "date_gate":           r"(datetime\.date|new Date|time\.time)[^<>=!]*[<>=!]+[^<>=!]*(20[2-9][0-9])",
    "hostname_gate":       r"(socket\.gethostname|os\.uname|os\.hostname)\(\)[^=]*==",
    "env_gate":            r"os\.environ\.get\(['\"](CI|GITHUB_ACTIONS)['\"]",

    # Misc
    "chmod_777":           r"chmod\s+777",
    "world_writable":      r"0o?777",

    # Crypto miners (drives BLOCK override)
    "crypto_miner":        r"\b(coinhive|cryptonight|xmrig|monero(?:-stratum)?|stratum\+tcp)\b",
}

# Map each pattern key to its scoring category (PRD §5.8 / §7).
PATTERN_CATEGORY: dict[str, str] = {
    "curl_pipe_sh":       "curl_pipe_shell",
    "wget_pipe_sh":       "curl_pipe_shell",

    "eval_call":          "obfuscation",
    "exec_call":          "obfuscation",
    "os_system":          "obfuscation",
    "subprocess_shell":   "obfuscation",
    "node_child_proc":    "obfuscation",
    "base64_decode_py":   "obfuscation",
    "base64_decode_js":   "obfuscation",
    "hex_decode":         "obfuscation",
    "rot13":              "obfuscation",

    "ssh_key_read":       "credential_targeting",
    "aws_env":            "credential_targeting",
    "private_key_marker": "credential_targeting",
    "passwd_read":        "credential_targeting",

    "nc_reverse":         "reverse_shell",
    "bash_tcp":           "reverse_shell",
    "ps_encoded":         "reverse_shell",
    "ps_webreq":          "reverse_shell",

    "date_gate":          "time_bomb",
    "hostname_gate":      "time_bomb",
    "env_gate":           "time_bomb",

    "chmod_777":          "obfuscation",
    "world_writable":     "obfuscation",

    "crypto_miner":       "crypto_miner",
}

# Severity per pattern category.
PATTERN_SEVERITY: dict[str, str] = {
    "curl_pipe_shell":      "high",
    "obfuscation":          "medium",
    "credential_targeting": "high",
    "reverse_shell":        "critical",
    "time_bomb":            "high",
    "crypto_miner":         "critical",
}


# ---------------------------------------------------------------------------
# Unicode trojan (PRD §5.9)
# ---------------------------------------------------------------------------

BIDI_CONTROL_CHARS: frozenset[str] = frozenset(
    {
        "‪", "‫", "‬", "‭", "‮",  # LRE, RLE, PDF, LRO, RLO
        "⁦", "⁧", "⁨", "⁩",            # LRI, RLI, FSI, PDI
        "‎", "‏", "؜",                      # LRM, RLM, ALM
    }
)

ZERO_WIDTH_CHARS: frozenset[str] = frozenset(
    {"​", "‌", "‍", "⁠", "﻿"}     # ZWSP, ZWNJ, ZWJ, WJ, BOM
)

# Cyrillic letters that look like Latin a/e/o/p/c/x.
HOMOGLYPH_CYRILLIC: frozenset[str] = frozenset(
    {"а", "е", "о", "р", "с", "х"}
)


# ---------------------------------------------------------------------------
# Scoring (PRD §7 — verbatim)
# ---------------------------------------------------------------------------

SCORING_WEIGHTS: dict[str, dict[str, int]] = {
    # Vulnerabilities
    "cve_critical":           {"per_finding": 10, "cap": 30},
    "cve_high":               {"per_finding": 5,  "cap": 20},

    # Secrets
    "verified_secret":        {"per_finding": 15, "cap": 30},
    "unverified_secret":      {"per_finding": 5,  "cap": 15},

    # Static analysis
    "semgrep_error":          {"per_finding": 5,  "cap": 20},
    "semgrep_warning":        {"per_finding": 2,  "cap": 10},

    # Risky files
    "npm_install_script":     {"per_finding": 15, "cap": 15},
    "setup_py_hook":          {"per_finding": 15, "cap": 15},
    "vscode_exec_config":     {"per_finding": 15, "cap": 15},
    "ci_workflow_risk":       {"per_finding": 10, "cap": 20},

    # Patterns
    "curl_pipe_shell":        {"per_finding": 15, "cap": 15},
    "obfuscation":            {"per_finding": 10, "cap": 20},
    "credential_targeting":   {"per_finding": 15, "cap": 30},
    "reverse_shell":          {"per_finding": 25, "cap": 25},
    "time_bomb":              {"per_finding": 20, "cap": 20},
    "crypto_miner":           {"per_finding": 25, "cap": 25},

    # Unicode
    "bidi_control_char":      {"per_finding": 30, "cap": 30},
    "zero_width_in_ident":    {"per_finding": 15, "cap": 15},
    "homoglyph":              {"per_finding": 8,  "cap": 16},

    # ML
    "unsafe_model_format":    {"per_finding": 15, "cap": 30},
    "modelscan_high":         {"per_finding": 20, "cap": 40},

    # Provenance
    "single_contributor":     {"per_finding": 3,  "cap": 3},
    "new_maintainer_account": {"per_finding": 10, "cap": 10},
    "star_velocity_spike":    {"per_finding": 5,  "cap": 5},
    "stale_repo":             {"per_finding": 2,  "cap": 2},

    # Dependency hygiene
    "typosquat_suspect":      {"per_finding": 20, "cap": 40},
    "unpinned_deps":          {"per_finding": 1,  "cap": 5},
}

VERDICT_THRESHOLDS: dict[str, tuple[int, int]] = {
    "LOW_RISK": (0, 24),
    "REVIEW":   (25, 59),
    "BLOCK":    (60, 100),
}

# Categories that force a BLOCK verdict regardless of score (PRD §7).
HARD_BLOCK_CATEGORIES: frozenset[str] = frozenset(
    {"bidi_control_char", "reverse_shell", "crypto_miner"}
)


# ---------------------------------------------------------------------------
# Risky file globs (PRD §5.7)
# ---------------------------------------------------------------------------

RISKY_FILES: dict[str, str] = {
    "package.json":            "Inspect for preinstall/postinstall/prepare scripts",
    "package-lock.json":       "Inspect for non-npmjs.org registries",
    "yarn.lock":               "Inspect for non-npmjs.org registries",
    "pnpm-lock.yaml":          "Inspect for non-npmjs.org registries",
    "setup.py":                "Inspect for custom cmdclass / dependency_links",
    "pyproject.toml":          "Inspect for build-system custom backends",
    "requirements.txt":        "Inspect for git/url/local entries",
}


# ---------------------------------------------------------------------------
# Install hints — used by `ossvet doctor` and skipped-scanner messages.
# ---------------------------------------------------------------------------

INSTALL_HINTS: dict[str, str] = {
    "semgrep":   "pip install semgrep   (or: brew install semgrep)",
    "syft":      "brew install syft     (or: see https://github.com/anchore/syft)",
    "grype":     "brew install grype    (or: see https://github.com/anchore/grype)",
    "gitleaks":  "brew install gitleaks (or: see https://github.com/gitleaks/gitleaks)",
    "scorecard": "brew install ossf/scorecard/scorecard (or: see https://github.com/ossf/scorecard)",
    "modelscan": "pip install modelscan",
    "git":       "Install git for your platform (https://git-scm.com).",
}
