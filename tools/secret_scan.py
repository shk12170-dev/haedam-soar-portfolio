"""저장소에 들어갈 파일에서 비밀값 흔적을 찾는다.

사용법:
    python tools/secret_scan.py [경로 ...]

인자가 없으면 `git ls-files`(추적 + 추적 예정 파일)를 검사한다.
경로가 폴더이면 그 아래 파일을 모두 검사한다.
발견하면 `파일:줄: 패턴이름`을 출력하고 종료 코드 1, 없으면 0.
값 자체는 출력하지 않는다(로그로 새지 않게).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PATTERNS: dict[str, re.Pattern[str]] = {
    "discord_webhook": re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{24,}"),
    "assigned_secret": re.compile(
        r"(?i)(api[_-]?key|token|secret|password|passwd|webhook[_-]?key)"
        r"[\"']?\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9/+_\-.]{16,})"
    ),
}

# 값 안에 이 문구가 있으면 자리표시·합성 시험값으로 보고 허용한다.
PLACEHOLDER_HINTS = (
    "change-me", "changeme", "replace-with", "replace_me", "example", "placeholder", "dummy", "xxxx",
    "test", "synthetic", "e2e-only", "-password",
)

# 이 파일에 적힌 경로(저장소 기준, 한 줄에 하나)는 검사하지 않는다. 예: 검사 도구 자체의 시험 파일
IGNORE_FILE = ".secretscanignore"

SKIP_DIRS = {".git", ".venv", "node_modules", "dist", "__pycache__", ".pytest_cache"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".iso", ".qcow2", ".vmdk"}


def is_placeholder(value: str) -> bool:
    low = value.lower()
    return low.startswith("${") or any(hint in low for hint in PLACEHOLDER_HINTS)


def is_code(line: str, match: re.Match[str]) -> bool:
    """값 자리에 문자열이 아니라 코드(함수 호출·속성 접근)가 온 경우."""
    value = match.group("value")
    after = line[match.end():match.end() + 1]
    quoted = line[match.start("value") - 1:match.start("value")] in ("'", '"')
    if after in ("(", "["):
        return True
    return not quoted and "." in value and value.split(".")[0].isidentifier()


def load_ignored() -> set[str]:
    path = Path(IGNORE_FILE)
    if not path.is_file():
        return set()
    lines = path.read_text(encoding="utf-8").splitlines()
    return {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}


def scan_text(text: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern in PATTERNS.items():
            for match in pattern.finditer(line):
                value = match.groupdict().get("value")
                if value is not None and (is_placeholder(value) or is_code(line, match)):
                    continue
                hits.append((lineno, name))
                break
    return hits


def iter_files(paths: list[str]) -> list[Path]:
    if not paths:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            capture_output=True, text=True, encoding="utf-8", check=True,
        ).stdout
        return [Path(p) for p in out.splitlines() if p]
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for child in p.rglob("*"):
                if child.is_file() and not SKIP_DIRS.intersection(child.parts):
                    files.append(child)
        elif p.is_file():
            files.append(p)
    return files


def main(argv: list[str]) -> int:
    found = 0
    ignored = load_ignored()
    for path in iter_files(argv):
        if path.suffix.lower() in SKIP_SUFFIXES or path.as_posix() in ignored:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, name in scan_text(text):
            print(f"{path.as_posix()}:{lineno}: {name}")
            found += 1
    if found:
        print(f"[secret_scan] {found}건 발견", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
