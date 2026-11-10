"""tools/secret_scan.py 동작 시험."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "tools" / "secret_scan.py"


def run_scan(tmp_path: Path, name: str, text: str) -> subprocess.CompletedProcess:
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCAN), str(target)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_flags_discord_webhook(tmp_path):
    result = run_scan(tmp_path, "a.txt", "url = https://discord.com/api/webhooks/123/abc\n")
    assert result.returncode == 1
    assert "discord_webhook" in result.stdout


def test_flags_private_key(tmp_path):
    result = run_scan(tmp_path, "k.txt", "-----BEGIN OPENSSH PRIVATE KEY-----\n")
    assert result.returncode == 1
    assert "private_key" in result.stdout


def test_flags_assigned_secret(tmp_path):
    result = run_scan(tmp_path, "c.yml", "api_key: 'Zx81kQ0pLmN3vB7tR2yW'\n")
    assert result.returncode == 1
    assert "assigned_secret" in result.stdout


def test_allows_placeholder(tmp_path):
    result = run_scan(
        tmp_path, ".env.example", "GRAYLOG_PASSWORD_SECRET=change-me-to-a-long-random-string\n"
    )
    assert result.returncode == 0, result.stdout


def test_allows_env_reference(tmp_path):
    result = run_scan(tmp_path, "compose.yaml", "password: ${MYSQL_PASSWORD:?set in .env}\n")
    assert result.returncode == 0, result.stdout


def test_allows_code_expressions(tmp_path):
    text = (
        "password = secrets.token_urlsafe(14)\n"
        "secret = current_app.config['RESPONSE_API_KEY']\n"
    )
    result = run_scan(tmp_path, "code.py", text)
    assert result.returncode == 0, result.stdout


def test_allows_synthetic_test_values(tmp_path):
    result = run_scan(tmp_path, "t.py", 'PASSWORD = "Synthetic-test-password-123"\n')
    assert result.returncode == 0, result.stdout


def test_still_flags_quoted_real_looking_value(tmp_path):
    result = run_scan(tmp_path, "s.py", 'password = "Qw8zLk2mPx9vRt4y"\n')
    assert result.returncode == 1


def test_reports_file_and_line(tmp_path):
    result = run_scan(tmp_path, "b.txt", "ok\nhttps://discordapp.com/api/webhooks/9/x\n")
    assert ":2:" in result.stdout


def test_clean_file_passes(tmp_path):
    result = run_scan(tmp_path, "clean.md", "# 제목\n평범한 문서입니다.\n")
    assert result.returncode == 0
