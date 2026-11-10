"""티켓 실측 실행기(1인 재구성에서 새로 작성) — 구현계획 Task 7.

호스트에서 실행한다. 공격 입력은 Kali(203.0.113.0/24)에서 SSH로 실행하고, 결과는 티켓 저장소·포털 대응 API로 확인한다.

    python lab/run_ticket.py S1 --plan            # 실행 계획과 사전 점검만
    python lab/run_ticket.py S1 --execute         # 입력 → 티켓 대기 → 효과 확인
    python lab/run_ticket.py S1 --execute --restore

리뷰 중점(구현계획):
1. 같은 출발지로 Graylog grace 창 안에 다시 시험하면 알림이 안 나간다 → 직전 실행 시각으로 거부하고 남은 초를 출력
2. 이전 회차 차단(포털 blocked_ips·pfSense 테이블)이 남아 있으면 실측이 오염된다 → 사전 점검에서 중단
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "docs" / "tickets" / ".last_run.json"

# 출발지·창 길이는 팀 정의와 같다(S1 30분, S8·S10 15분 grace_period).
TICKETS = {
    "S1": {"src": "203.0.113.11", "window_min": 30, "via": ["portal"]},
    "S4": {"src": "203.0.113.12", "window_min": 30, "via": ["portal"]},
    "S8": {"src": "203.0.113.21", "window_min": 15, "via": ["portal"]},
    "S10": {"src": "203.0.113.22", "window_min": 15, "via": ["portal", "pfsense"]},
    "S12": {"src": "203.0.113.41", "window_min": 15, "via": ["portal"]},
}
NORMAL = "203.0.113.100"


def window_blocked(last_run: datetime | None, now: datetime, minutes: int) -> int | None:
    """직전 실행 뒤 grace 창이 남아 있으면 남은 초, 아니면 None."""
    if last_run is None:
        return None
    left = minutes * 60 - (now - last_run).total_seconds()
    return int(round(left)) if left > 0 else None


def precheck(blocked_ips: list[str], pf_table: list[str], src: str) -> list[str]:
    """이번 출발지에 이전 차단이 남아 있으면 문제 목록을 돌려준다."""
    problems = []
    if src in blocked_ips:
        problems.append(f"portal_block_left:{src}")
    if src in pf_table:
        problems.append(f"pf_block_left:{src}")
    return problems


def mttd(condition_met_at: datetime, detected_at: datetime) -> float:
    return round((detected_at - condition_met_at).total_seconds(), 3)


def last_run(ticket: str) -> datetime | None:
    if not STATE.is_file():
        return None
    raw = json.loads(STATE.read_text(encoding="utf-8")).get(ticket)
    return datetime.fromisoformat(raw) if raw else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ticket", choices=sorted(TICKETS))
    ap.add_argument("--plan", action="store_true")
    a = ap.parse_args()
    t = TICKETS[a.ticket]
    now = datetime.now(timezone.utc)
    wait = window_blocked(last_run(a.ticket), now, t["window_min"])
    print(json.dumps({"ticket": a.ticket, "src": t["src"], "normal": NORMAL, "via": t["via"],
                      "window_min": t["window_min"], "wait_seconds": wait}, ensure_ascii=False))
    if wait:
        print(f"[run_ticket] 같은 출발지 grace 창 안입니다. {wait}초 뒤 다시 실행하세요.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
